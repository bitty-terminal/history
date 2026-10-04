-- Entry point for the History keeper (bitty-terminal.history): opt-in history
-- policy over the PUBLIC history-read host API only.
--
-- Accepted contracts: RFC-0004 (history-read surface, bitty-docs, accepted),
-- W-131 (storage-and-history boundary, bitty-docs, accepted), and W-137
-- (plugin history-and-storage policy, bitty-plugins-docs, accepted). This
-- file re-expresses the keeper half of that boundary as extension-side
-- policy: scoped, bounded snapshot reads over the three queryable sources
-- (segmented transcript, command history, own per-plugin KV) through
-- `bitty.history.*.query`. It never opens a stream, never polls its way
-- into one, never widens a scope, never touches Terminal Truth, and never
-- reads what was never persisted.
--
-- Source table (RFC-0004, mirrored by Core `HistorySource` at bitty
-- 76fa42d6 and the SDK W-139 surface at bitty-plugin-sdk PR #144 head):
--   transcript : sealed transcript segments while opt-in capture holds;
--   commands   : scoped list, search, and tail reads over command history;
--   kv         : reads of the plugin's own KV namespace only, under the
--                published quota ceilings (cross-plugin reads are
--                unrepresentable and terminal-derived shims are forbidden).
-- Session snapshots are absent deliberately: save/restore is a Core-only
-- mechanism per W-137, and `session`/`snapshot`/`session-snapshot` sources
-- fail closed here before any host call.
--
-- Grant-combination rule (RFC-0004): reading authorizes delivery of results
-- into the plugin VM only. Copying to the clipboard, exporting to files,
-- spawning processes, or invoking external history systems each needs its
-- own separately granted authority; the history grant never implies them.
-- This plugin declares no export capability and performs no export: bodies
-- are treated as untrusted content (labeled, never instructions) and never
-- routed into an instruction channel.
--
-- The host evaluates this file once per plugin activation and owns every
-- resource created here for the lifetime of that generation. The code stays
-- inside the Lua 5.1 grammar (the `just lua` gate) and uses no `utf8`
-- library: all bounds are byte bounds and `#s` is a byte count.
--
-- Denials are typed and oracle-tight (RFC-0004 taxonomy, mirrored by Core
-- `HistoryDenialKind::code` at 76fa42d6 and the SDK mock at PR #144 head):
-- missing grant, revoked-or-expired grant, scope mismatch, over-bound or
-- over-rate request, capture-disabled source, safe-mode denial, unknown
-- trust or domain, and purged-or-expired content (typed unavailability,
-- never a silent gap, never resurrected). Denial shapes never vary with
-- out-of-scope facts: no denial carries content bytes, foreign identifiers,
-- or any absent-versus-denied signal.

local M = {}

M.PLUGIN_ID = "bitty-terminal.history"

-- Bounds mirrored from the accepted shape (SDK W-139 mock placeholders at
-- PR #144 head, themselves mirroring Core PR #1673 test caps; the SHAPE is
-- normative, exact numbers stay parked to W-137/W-139/W-146 and are never
-- wire truth): explicit row range plus count/size caps per query, needle
-- bound, scope-id bound. Over-bound requests deny (host authoritative);
-- this module never clamps silently.
M.MAX_ROWS_PER_QUERY = 16
M.MAX_BYTES_PER_QUERY = 4096
M.MAX_BYTES_PER_ROW = 256
M.MAX_NEEDLE_BYTES = 256
M.MAX_SCOPE_ID_BYTES = 128
M.REQUIRED_API_MAJOR = 1 -- manifest declares plugin-api ^1.0; same gate here

-- Core-attached labels (RFC-0004 P0-AC-024; Core `UntrustedLabel::VALUE`,
-- SDK `HISTORY_UNTRUSTED_LABEL`; freshness `HISTORY_FRESHNESS`).
M.UNTRUSTED_LABEL = "untrusted-observation"
M.FRESHNESS = "point-in-time-no-guarantee"

-- Queryable sources; session snapshots are never a source.
M.SOURCES = { "transcript", "commands", "kv" }

-- Not-open/disabled sentinels surfaced through the scalar queries below.
M.CODE_DISABLED = "E_DISABLED"
M.CODE_NO_HOST = "NO_HOST"

-- Complete denial vocabulary this module can surface (host-authoritative;
-- client-side validation emits only the E_DEF_INVALID / scope-mismatch /
-- over-bound subset before any host call).
M.DENIAL_CODES = {
  "E_HISTORY_MISSING_GRANT",
  "E_HISTORY_REVOKED_GRANT",
  "E_HISTORY_SCOPE_MISMATCH",
  "E_HISTORY_OVER_BOUND",
  "E_HISTORY_CAPTURE_DISABLED",
  "E_HISTORY_SAFE_MODE",
  "E_HISTORY_TRUST_DENIED",
  "E_HISTORY_UNAVAILABLE",
  "E_DEF_INVALID",
}

-- ---------------------------------------------------------------------------
-- Pure policy: source, scope, and bound validation (no host needed)
-- ---------------------------------------------------------------------------

local function is_source(s)
  return s == "transcript" or s == "commands" or s == "kv"
end

local function is_forbidden_source(s)
  return s == "session" or s == "snapshot" or s == "session-snapshot"
end

-- One scope-id axis: 1..128 bytes, never '*' or 'all' (case-insensitive),
-- no ASCII control or whitespace (bytes <= 32 or == 127); non-ASCII bytes
-- (>= 128) pass as UTF-8 continuation/content bytes.
local function bad_scope_id(value)
  if type(value) ~= "string" then
    return true
  end
  if #value == 0 or #value > M.MAX_SCOPE_ID_BYTES then
    return true
  end
  if value == "*" then
    return true
  end
  local lowered = string.lower(value)
  if lowered == "all" then
    return true
  end
  for i = 1, #value do
    local b = string.byte(value, i)
    if b <= 32 or b == 127 then
      return true
    end
  end
  return false
end

-- Command args cross the engine bridge as indexable bridged objects
-- (userdata), not Lua tables: field reads work but type() is not "table"
-- and pairs() does not apply. Normalization copies the known query fields
-- into fresh Lua tables so validation below sees one shape. Unknown shapes
-- (strings, numbers) pass through so the validator rejects them.
local function normalize_scope_value(scope)
  if scope == nil then
    return nil
  end
  if type(scope) == "table" then
    return scope
  end
  if type(scope) == "userdata" then
    return { panel = scope.panel, workspace = scope.workspace }
  end
  return scope
end

local function normalize_opts_value(opts)
  if opts == nil then
    return {}
  end
  if type(opts) == "table" then
    return opts
  end
  if type(opts) == "userdata" then
    return {
      scope = normalize_scope_value(opts.scope),
      row_start = opts.row_start,
      row_count = opts.row_count,
      max_bytes = opts.max_bytes,
      op = opts.op,
      needle = opts.needle,
    }
  end
  return opts
end

-- Validates the explicit scope for one source. Returns panel, workspace
-- (each a string or nil) or nil plus a code and reason. Client-side twin of
-- the host gate: malformed ids are E_DEF_INVALID, unscoped
-- transcript/commands queries are E_HISTORY_SCOPE_MISMATCH, and any
-- panel/workspace extent on kv is E_DEF_INVALID (the caller namespace *is*
-- the kv scope; cross-plugin reads are unrepresentable).
function M.validate_scope(source, scope)
  scope = normalize_scope_value(scope)
  if scope ~= nil and type(scope) ~= "table" then
    return nil, "E_DEF_INVALID", "scope must be a table"
  end
  local panel = nil
  local workspace = nil
  if scope ~= nil then
    panel = scope.panel
    workspace = scope.workspace
  end
  if panel ~= nil and type(panel) ~= "string" then
    return nil, "E_DEF_INVALID", "scope.panel must be a string"
  end
  if workspace ~= nil and type(workspace) ~= "string" then
    return nil, "E_DEF_INVALID", "scope.workspace must be a string"
  end
  if panel ~= nil and bad_scope_id(panel) then
    return nil, "E_DEF_INVALID", "scope.panel must be 1..128 non-blank bytes, never '*' or 'all'"
  end
  if workspace ~= nil and bad_scope_id(workspace) then
    return nil, "E_DEF_INVALID", "scope.workspace must be 1..128 non-blank bytes, never '*' or 'all'"
  end
  if source == "kv" then
    if panel ~= nil or workspace ~= nil then
      return nil, "E_DEF_INVALID", "kv scope is the caller namespace; panel/workspace extents are rejected"
    end
    return { panel = nil, workspace = nil }, nil, nil
  end
  if panel == nil and workspace == nil then
    return nil, "E_HISTORY_SCOPE_MISMATCH", "history query scope names no panel or workspace extent"
  end
  return { panel = panel, workspace = workspace }, nil, nil
end

-- Validates the bounded-query shape. Returns a normalized opts table or nil
-- plus a code and reason. Explicit row_count/max_bytes over zero are
-- required (missing or zero denies as over-bound, mirroring the host);
-- over-ceiling values pass through so the host denies (never silently
-- clamped). The needle rule (1..256 bytes, required iff search) is enforced
-- here as over-bound, mirroring the host.
function M.validate_query(source, opts)
  if not is_source(source) then
    if is_forbidden_source(source) then
      return nil, "E_DEF_INVALID", "session snapshots are Core-only; '" .. tostring(source) .. "' is never queryable"
    end
    return nil, "E_DEF_INVALID", "unknown history source '" .. tostring(source) .. "'"
  end
  if opts ~= nil and type(opts) ~= "table" then
    -- Bridged command args arrive as userdata; normalize before judging.
    opts = normalize_opts_value(opts)
  end
  if opts ~= nil and type(opts) ~= "table" then
    return nil, "E_DEF_INVALID", "opts must be a table"
  end
  local t = opts or {}
  local scope, scode, sreason = M.validate_scope(source, t.scope)
  if scope == nil then
    return nil, scode, sreason
  end
  local op = t.op
  if op == nil then
    op = "list"
  end
  if op ~= "list" and op ~= "tail" and op ~= "search" then
    return nil, "E_DEF_INVALID", "op must be list, tail, or search"
  end
  local row_start = t.row_start
  if row_start == nil then
    row_start = 0
  end
  if type(row_start) ~= "number" or math.floor(row_start) ~= row_start or row_start < 0 then
    return nil, "E_DEF_INVALID", "row_start must be a nonnegative integer"
  end
  local row_count = t.row_count
  if type(row_count) ~= "number" or math.floor(row_count) ~= row_count or row_count <= 0 then
    return nil, "E_HISTORY_OVER_BOUND", "history query needs an explicit row bound over zero"
  end
  local max_bytes = t.max_bytes
  if type(max_bytes) ~= "number" or math.floor(max_bytes) ~= max_bytes or max_bytes <= 0 then
    return nil, "E_HISTORY_OVER_BOUND", "history query needs an explicit byte bound over zero"
  end
  local needle = nil
  if op == "search" then
    needle = t.needle
    if type(needle) ~= "string" or #needle == 0 or #needle > M.MAX_NEEDLE_BYTES then
      return nil, "E_HISTORY_OVER_BOUND", "history search needle must be 1..256 bytes"
    end
  end
  return {
    scope = scope,
    row_start = row_start,
    row_count = row_count,
    max_bytes = max_bytes,
    op = op,
    needle = needle,
  }, nil, nil
end

-- ---------------------------------------------------------------------------
-- Compatibility gate: no partial activation on version mismatch
-- ---------------------------------------------------------------------------

-- The manifest declares plugin-api ^1.0 and the host validates before
-- activation; this is the defense-in-depth twin inside the plugin. When the
-- check fails the module registers nothing (no commands) and only records
-- the diagnostic.
function M.check_compat(api_version)
  if type(api_version) ~= "string" then
    return false, "plugin API version is not a string"
  end
  local major = string.match(api_version, "^(%d+)%.")
  if major == nil then
    return false, "unparsable plugin API version '" .. api_version .. "'"
  end
  if tonumber(major) ~= M.REQUIRED_API_MAJOR then
    return false, "requires Plugin API ^1.0, host provides '" .. api_version .. "'"
  end
  return true
end

-- ---------------------------------------------------------------------------
-- Snapshot queries over the public host API (one-shot, never streaming)
-- ---------------------------------------------------------------------------

M.disabled = false
M.disabled_reason = ""

local state = {
  last_code = "ok",
  last_detail = "",
  last_page = nil,
}

local function note(code, detail)
  state.last_code = code
  state.last_detail = detail or ""
end

-- Host-dependent entries below require the injected `bitty` table; the pure
-- policy above (source, scope, bounds, compat gate) works without it. The
-- injected host value arrives as engine userdata, so presence is tested with
-- a nil comparison rather than a type check.
local function has_host()
  return bitty ~= nil
end

-- Extracts the E_* host code from a pcall error for typed diagnostics.
local function host_code(err)
  local text = tostring(err)
  local code = string.match(text, "(E_[A-Z_]+)")
  if code ~= nil then
    return code
  end
  return "E_UNKNOWN"
end

-- Host calls return indexable engine values (tables or bridged objects);
-- only nil means "no value". Never gate host-provided values on
-- type() == "table".
local function page_records(page)
  if page == nil then
    return nil
  end
  return page.records
end

-- Verifies one host-delivered page before the plugin trusts it: freshness
-- is exactly point-in-time-no-guarantee, every record is redacted with the
-- Core-attached untrusted label surviving, and every record carries
-- attribution. Failure fails closed (never delivered as instructions).
local function verify_page(page)
  if page == nil then
    return false, "page returned no value"
  end
  if page.freshness ~= M.FRESHNESS then
    return false, "page freshness must be '" .. M.FRESHNESS .. "'"
  end
  local records = page_records(page)
  if records == nil then
    return false, "page records missing"
  end
  local n = 0
  for _, rec in ipairs(records) do
    n = n + 1
    if rec.redacted ~= true then
      return false, "record " .. tostring(n) .. " is not redacted"
    end
    if rec.label ~= M.UNTRUSTED_LABEL then
      return false, "record " .. tostring(n) .. " misses the untrusted label"
    end
    if rec.body == nil or type(rec.body) ~= "string" then
      return false, "record " .. tostring(n) .. " body missing"
    end
    if rec.truncated == nil then
      return false, "record " .. tostring(n) .. " truncated flag missing"
    end
    if rec.attribution == nil then
      return false, "record " .. tostring(n) .. " attribution missing"
    end
  end
  if page.total_in_scope == nil or type(page.total_in_scope) ~= "number" then
    return false, "page total_in_scope missing"
  end
  return true
end

-- Scalar state queries for tests and diagnostics (plain values only).
function M.last_code()
  return state.last_code
end

function M.last_detail()
  return state.last_detail
end

function M.last_page()
  return state.last_page
end

function M.record_count()
  if state.last_page == nil then
    return 0
  end
  local records = page_records(state.last_page)
  if records == nil then
    return 0
  end
  local n = 0
  for _ in ipairs(records) do
    n = n + 1
  end
  return n
end

-- Record bodies are untrusted content under the prompt-injection rule: this
-- helper returns them for display only and never executes, interpolates, or
-- routes them into an instruction channel.
function M.record_body(index)
  if state.last_page == nil then
    return nil
  end
  local records = page_records(state.last_page)
  if records == nil then
    return nil
  end
  local rec = records[index]
  if rec == nil then
    return nil
  end
  return rec.body
end

function M.record_label(index)
  if state.last_page == nil then
    return nil
  end
  local records = page_records(state.last_page)
  if records == nil then
    return nil
  end
  local rec = records[index]
  if rec == nil then
    return nil
  end
  return rec.label
end

-- One-shot bounded snapshot query over already-persisted state. Builds the
-- explicit host opts (scope, row range, caps, op, needle), calls the
-- per-source surface under the NEW `bitty.history` root, and verifies the
-- delivered page (redacted, labeled, attributed, point-in-time). Any denial
-- -- missing or revoked grant, scope mismatch, over-bound, capture
-- disabled, safe mode, trust denial, purged content -- surfaces as its
-- typed E_* code with the page left untouched. No subscription, no watch,
-- no tail-follow, no cursor held across calls: a caller that wants newer
-- state issues a new bounded query under its grant.
function M.query(source, opts)
  if not has_host() then
    return false, M.CODE_NO_HOST
  end
  if M.disabled then
    return false, M.CODE_DISABLED
  end
  if not is_source(source) then
    if is_forbidden_source(source) then
      note("E_DEF_INVALID", "session snapshots are Core-only; '" .. tostring(source) .. "' is never queryable")
      return false, state.last_code
    end
    note("E_DEF_INVALID", "unknown history source '" .. tostring(source) .. "'")
    return false, state.last_code
  end
  local norm, code, reason = M.validate_query(source, opts)
  if norm == nil then
    note(code, reason)
    return false, state.last_code
  end
  local host_opts = {
    scope = {},
    row_start = norm.row_start,
    row_count = norm.row_count,
    max_bytes = norm.max_bytes,
    op = norm.op,
  }
  if norm.scope.panel ~= nil then
    host_opts.scope.panel = norm.scope.panel
  end
  if norm.scope.workspace ~= nil then
    host_opts.scope.workspace = norm.scope.workspace
  end
  if norm.needle ~= nil then
    host_opts.needle = norm.needle
  end
  local surface = bitty.history[source].query
  if surface == nil then
    note("E_UNKNOWN", "history surface '" .. tostring(source) .. ".query' absent")
    return false, state.last_code
  end
  local ok, page = pcall(surface, host_opts)
  if not ok then
    note(host_code(page), "history query denied; no state changed")
    return false, state.last_code
  end
  local verified, why = verify_page(page)
  if not verified then
    note("E_UNKNOWN", "history page failed verification: " .. tostring(why))
    return false, state.last_code
  end
  state.last_page = page
  note("ok", "")
  return true, "ok"
end

-- ---------------------------------------------------------------------------
-- Host wiring. Skipped when the host table is absent so the pure policy
-- above (source, scope, bounds, compat gate) stays loadable on its own.
-- ---------------------------------------------------------------------------

-- Diagnostic entry point for tests and operators. Set before the host guard
-- so it exists in every mode.
if history == nil then
  history = M
end

if bitty == nil then
  return M
end

do
  local compat_ok, compat_err = M.check_compat(bitty.api_version)
  if not compat_ok then
    -- Version/capability mismatch disables with a diagnostic and no partial
    -- activation: nothing below runs, so no command exists for this
    -- generation.
    M.disabled = true
    M.disabled_reason = compat_err
    note(M.CODE_DISABLED, compat_err)
    return M
  end

  local function query_schema()
    return {
      type = "object",
      properties = {
        scope = {
          type = "object",
          properties = {
            panel = { type = "string" },
            workspace = { type = "string" },
          },
          additionalProperties = false,
        },
        row_start = { type = "number", minimum = 0 },
        row_count = { type = "number", minimum = 1 },
        max_bytes = { type = "number", minimum = 1 },
        op = { type = "string" },
        needle = { type = "string" },
      },
      additionalProperties = false,
    }
  end

  bitty.commands.register({
    id = "query-transcript",
    title = "History: query transcript",
    description = "One-shot bounded snapshot over sealed transcript segments while opt-in capture holds; typed denial or a redacted labeled page.",
    args_schema = query_schema(),
    run = function(args)
      local ok, code = M.query("transcript", args)
      return { ok = ok, code = code }
    end,
  })

  bitty.commands.register({
    id = "query-commands",
    title = "History: query commands",
    description = "One-shot scoped list, search, or tail read over command history; typed denial or a redacted labeled page.",
    args_schema = query_schema(),
    run = function(args)
      local ok, code = M.query("commands", args)
      return { ok = ok, code = code }
    end,
  })

  bitty.commands.register({
    id = "query-kv",
    title = "History: query own KV",
    description = "One-shot snapshot read of the plugin own KV namespace only; cross-plugin reads are unrepresentable.",
    args_schema = query_schema(),
    run = function(args)
      local ok, code = M.query("kv", args)
      return { ok = ok, code = code }
    end,
  })

  -- No event subscriptions: queries are snapshots, never streams. No
  -- keymap suggestions: history queries carry no chord vocabulary.
end

return M
