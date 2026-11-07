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
-- Presentation (bitty#2967): a successful query paints its page into the
-- single focusable overlay (accepted W-01 overlay-input-capture contract,
-- capability `ui.overlay.focus`). The data path and the paint path stay
-- separate: the query stores the verified page, and the command entry point
-- presents it, so a host without the overlay surface (or a generation whose
-- consent omitted the grant) still answers with the typed `{ok, code}` result
-- and simply paints nothing. The overlay is a static snapshot viewer, never
-- an input surface: Core owns `Esc`, focus-switch, and idle-timeout
-- revocation, and this module never polls for input.
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

-- Presentation bounds (accepted W-01 overlay surface). `ui.overlay.update`
-- is a per-call 4096-byte surface, so a page whose rows do not fit is painted
-- as a bounded prefix plus a typed note instead of being rejected by the host
-- and leaving the overlay blank. `MAX_SCENE_TEXT_BYTES` is the JSON-escaped
-- text budget; the reserve covers the scene JSON structure for the maximum
-- node count (title + 16 rows + 2 notes, ~26 bytes per `Text` node plus the
-- `List` wrapper). Bodies are host `String`s (valid UTF-8), so one Lua byte
-- is one JSON payload byte unless escaping grows it, which `escaped_bytes`
-- accounts for.
M.OVERLAY_CALL_MAX_BYTES = 4096
M.SCENE_STRUCTURE_RESERVE_BYTES = 576
M.MAX_SCENE_TEXT_BYTES = M.OVERLAY_CALL_MAX_BYTES - M.SCENE_STRUCTURE_RESERVE_BYTES
M.SCENE_NOTE_RESERVE_BYTES = 96
M.SCENE_TITLE_PREFIX = "History: "
M.SCENE_PLACEHOLDER = "Esc closes"
M.EMPTY_NOTE = "No records in scope"
M.NOTE_SKIPPED_PREFIX = "records skipped: "
M.NOTE_OMITTED_PREFIX = "rows not shown: "
-- Display-note tags (lowercase on purpose: the `E_*` vocabulary stays
-- reserved for host denials and client policy codes).
M.NOTE_INVALID_RECORD = "invalid-record"
M.NOTE_OVERLAY_BUDGET = "overlay-budget"

-- Queryable sources; session snapshots are never a source.
M.SOURCES = { "transcript", "commands", "kv" }

-- Bounded default context (command path). A keybinding dispatches a command
-- with no arguments, and an empty table carries no scope and no bounds. The
-- public Lua surface exposes no focus getter: resolving the focused
-- panel/workspace through `workspace.list` or `panel.*` would require
-- `workspace.read`/`panel.focus`, a capability widening this package must not
-- take. The sanctioned, capability-neutral host context is the plugin's
-- declared settings namespace (`[settings]` in the manifest), which the host
-- resolves per generation and the plugin reads per query. Explicit arguments
-- always win; defaults are convenience values, never authority, and the host
-- still intersects every query scope with the granted scope.
M.SETTING_DEFAULT_PANEL = "default_panel"
M.SETTING_DEFAULT_WORKSPACE = "default_workspace"
M.SETTING_ROW_COUNT = "row_count"
M.SETTING_MAX_BYTES = "max_bytes"

-- Shipped bounds for an argument-free query: the accepted per-query caps, so
-- an empty dispatch returns the widest page the host allows and never more.
-- Configured defaults are accepted only inside the same 1..cap window; a
-- value outside it falls back to these shipped values (a local default is
-- never allowed to turn into an over-bound request the host must deny).
M.DEFAULT_ROW_COUNT = M.MAX_ROWS_PER_QUERY
M.DEFAULT_MAX_BYTES = M.MAX_BYTES_PER_QUERY

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
  -- Admitted records for the last successful page (plain `{body,label}`
  -- pairs) plus the count of records dropped by admission, so the paint path
  -- never re-walks untrusted host structures.
  last_records = {},
  skipped_records = 0,
  -- Last scene successfully presented to the overlay (diagnostics/tests).
  last_scene = nil,
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

-- Reads one declared setting from the host's plugin settings namespace.
-- Absent host, absent settings bridge, a denied read, or a nil/absent value
-- all yield nil: bounded defaults are convenience values, never authority,
-- and a settings problem must not abort a query or activation. The host (and
-- the SDK mock) already filter undeclared keys and wrong-typed values.
local function setting_value(key)
  if not has_host() or bitty.settings == nil then
    return nil
  end
  local ok, value = pcall(bitty.settings.get, key)
  if not ok then
    return nil
  end
  return value
end

-- Validates one default scope axis. Returns value or nil, plus a code and
-- reason on a malformed default. An empty string means "no bound context"
-- (the shipped manifest default), never a wildcard.
local function default_scope_axis(axis, value)
  if value == nil then
    return nil, nil, nil
  end
  if type(value) ~= "string" then
    return nil, "E_DEF_INVALID", "default scope." .. axis .. " must be a string"
  end
  if value == "" then
    return nil, nil, nil
  end
  if bad_scope_id(value) then
    return nil, "E_DEF_INVALID",
      "default scope." .. axis .. " must be 1..128 non-blank bytes, never '*' or 'all'"
  end
  return value, nil, nil
end

-- Resolves the scope for one query. Explicit args win unchanged (the caller
-- may name one axis, both, or malformed values; the unchanged validator and
-- the host remain authoritative). Only when neither axis is named does the
-- declared settings context supply the bounded default, and only when that
-- context yields at least one valid axis; otherwise the typed scope-mismatch
-- denial is preserved. KV has no extent to resolve: the caller namespace is
-- the scope, and panel/workspace defaults never apply.
function M.resolve_scope(source, scope)
  local explicit = normalize_scope_value(scope)
  if explicit ~= nil then
    if type(explicit) ~= "table" then
      -- Malformed shape: hand it to the unchanged validator.
      return explicit, nil, nil
    end
    if explicit.panel ~= nil or explicit.workspace ~= nil then
      return explicit, nil, nil
    end
  end
  if source == "kv" then
    return explicit or {}, nil, nil
  end
  local panel, pcode, preason =
    default_scope_axis("panel", setting_value(M.SETTING_DEFAULT_PANEL))
  if panel == nil and pcode ~= nil then
    return nil, pcode, preason
  end
  local workspace, wcode, wreason =
    default_scope_axis("workspace", setting_value(M.SETTING_DEFAULT_WORKSPACE))
  if workspace == nil and wcode ~= nil then
    return nil, wcode, wreason
  end
  if panel == nil and workspace == nil then
    return nil, "E_HISTORY_SCOPE_MISMATCH",
      "history query scope names no panel or workspace extent and no bounded default context is configured"
  end
  return { panel = panel, workspace = workspace }, nil, nil
end

-- Applies the bounded-default row/byte window when a bound is absent. An
-- explicit bound travels through unchanged so the validator/host still deny
-- over-bound requests (never clamped). A configured default outside the
-- accepted 1..cap window falls back to the shipped cap, so a local default
-- can never become an over-bound request.
local function bounded_default(value, key, shipped, cap)
  if value ~= nil then
    return value
  end
  local configured = setting_value(key)
  if type(configured) == "number" and math.floor(configured) == configured
      and configured >= 1 and configured <= cap then
    return configured
  end
  return shipped
end

function M.resolve_bounds(opts)
  local row_count = bounded_default(
    opts.row_count, M.SETTING_ROW_COUNT, M.DEFAULT_ROW_COUNT, M.MAX_ROWS_PER_QUERY)
  local max_bytes = bounded_default(
    opts.max_bytes, M.SETTING_MAX_BYTES, M.DEFAULT_MAX_BYTES, M.MAX_BYTES_PER_QUERY)
  return row_count, max_bytes
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

-- Verifies one host-delivered page before the plugin trusts it: freshness is
-- exactly point-in-time-no-guarantee, the record list is present, and the
-- scope total is a number. Failure fails closed (nothing is delivered).
--
-- Per-record admission is a separate step (see `collect_records`): a record
-- that misses the redaction/label/body/truncation/attribution contract is
-- dropped from the delivered set and counted, never trusted and never
-- painted, so one malformed record cannot blank the whole answer.
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
  if page.total_in_scope == nil or type(page.total_in_scope) ~= "number" then
    return false, "page total_in_scope missing"
  end
  return true
end

-- Admits records one by one into a fresh Lua table of plain `{body,label}`
-- pairs. A record is admitted only when it is redacted, carries the
-- Core-attached untrusted label, has a string body, and reports truncation
-- and attribution. Returns the admitted list plus the skipped count (the
-- typed note the presentation layer paints).
function M.collect_records(page)
  local records = page_records(page)
  if records == nil then
    return {}, 0
  end
  local admitted = {}
  local skipped = 0
  for _, rec in ipairs(records) do
    local valid = rec ~= nil
      and rec.redacted == true
      and rec.label == M.UNTRUSTED_LABEL
      and type(rec.body) == "string"
      and rec.truncated ~= nil
      and rec.attribution ~= nil
    if valid then
      admitted[#admitted + 1] = { body = rec.body, label = rec.label }
    else
      skipped = skipped + 1
    end
  end
  return admitted, skipped
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

function M.last_scene()
  return state.last_scene
end

function M.skipped_count()
  return state.skipped_records
end

function M.record_count()
  return #state.last_records
end

-- Record bodies are untrusted content under the prompt-injection rule: this
-- helper returns them for display only and never executes, interpolates, or
-- routes them into an instruction channel.
function M.record_body(index)
  local rec = state.last_records[index]
  if rec == nil then
    return nil
  end
  return rec.body
end

function M.record_label(index)
  local rec = state.last_records[index]
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
  -- An empty dispatch (keybinding/palette) carries no scope and no bounds.
  -- Resolve the bounded default context before validation; explicit scope and
  -- explicit bounds still take the unchanged path and the host stays
  -- authoritative for every grant/scope/rate decision.
  local normalized = opts
  if normalized == nil then
    normalized = {}
  elseif type(normalized) ~= "table" then
    normalized = normalize_opts_value(normalized)
  end
  if type(normalized) == "table" then
    local resolved, scode, sreason = M.resolve_scope(source, normalized.scope)
    if resolved == nil then
      note(scode, sreason)
      return false, state.last_code
    end
    normalized.scope = resolved
    local rows, bytes = M.resolve_bounds(normalized)
    normalized.row_count = rows
    normalized.max_bytes = bytes
  end
  local norm, code, reason = M.validate_query(source, normalized)
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
  local records, skipped = M.collect_records(page)
  state.last_page = page
  state.last_records = records
  state.skipped_records = skipped
  note("ok", "")
  return true, "ok"
end

-- ---------------------------------------------------------------------------
-- Presentation: paint the latest answer into the focusable overlay
-- ---------------------------------------------------------------------------
--
-- One overlay session serves all three commands. `bitty.ui.overlay.acquire`
-- mounts the surface and starts the capture in one Core-owned switch, and
-- `bitty.ui.overlay.update` replaces the scene. Core surfaces only the
-- capture owner's block, so the acquire is what makes the transcript visible;
-- a query that returns `{ok, code}` without an acquire would answer with no
-- surface at all (bitty#2967).
--
-- The session is held while the user reads: Core owns `Esc`, focus-switch,
-- idle-timeout, unload, and crash revocation, and emits `overlay.released`
-- for observers. This module keeps no subscription; instead every paint
-- treats an update rejection as a stale session, drops the handle, and
-- acquires one fresh surface (a released handle can never be updated).
-- Presentation never fails the data path: every host call is guarded and a
-- missing `bitty.ui` bridge, a missing grant, a foreign capture, or a
-- rejected scene degrades to a data-only answer.

local overlay_handle = nil

-- The W-01 overlay table, or nil on a host that predates it. The injected
-- bridge arrives as engine userdata (field reads work, `type()` is not
-- "table"), so only nil means absent. Checked on every use (never cached) so
-- a mid-generation bridge change cannot wedge a paint.
local function overlay_table()
  if not has_host() then
    return nil
  end
  local ui = bitty.ui
  if ui == nil then
    return nil
  end
  return ui.overlay
end

local function scene_title(source)
  return M.SCENE_TITLE_PREFIX .. tostring(source)
end

-- JSON-escaped byte length of one text run. The host bounds an overlay update
-- by the JSON payload, and JSON escaping grows `"`, `\`, and control bytes, so
-- the budget below must account for the escaped size rather than `#text`.
function M.escaped_bytes(text)
  local total = 0
  for index = 1, #text do
    local byte = string.byte(text, index)
    if byte == 34 or byte == 92 then
      total = total + 2
    elseif byte < 32 then
      total = total + 6
    else
      total = total + 1
    end
  end
  return total
end

-- Build the scene for one answer: a title row, the admitted record bodies in
-- host order, and typed notes for skipped and not-shown rows. Never empty, so
-- a surfaced overlay always paints either rows or an explicit "no records"
-- line. Rows that would cross the per-update call ceiling are not shown and
-- are reported by count instead of being silently dropped by the host.
function M.build_scene(source, records, skipped)
  local children = { { kind = "Text", text = scene_title(source) } }
  local used = M.escaped_bytes(children[1].text)
  local skipped_note = nil
  local reserved = M.SCENE_NOTE_RESERVE_BYTES
  if skipped > 0 then
    skipped_note = M.NOTE_SKIPPED_PREFIX .. tostring(skipped)
      .. " (" .. M.NOTE_INVALID_RECORD .. ")"
    reserved = reserved + M.escaped_bytes(skipped_note)
  end
  local shown = 0
  for index, record in ipairs(records) do
    local cost = M.escaped_bytes(record.body)
    if used + reserved + cost > M.MAX_SCENE_TEXT_BYTES then
      break
    end
    used = used + cost
    shown = index
    children[#children + 1] = { kind = "Text", text = record.body }
  end
  local omitted = #records - shown
  if omitted > 0 then
    children[#children + 1] = {
      kind = "Text",
      text = M.NOTE_OMITTED_PREFIX .. tostring(omitted)
        .. " (" .. M.NOTE_OVERLAY_BUDGET .. ")",
    }
  end
  if skipped_note ~= nil then
    children[#children + 1] = { kind = "Text", text = skipped_note }
  end
  if #records == 0 and skipped == 0 then
    children[#children + 1] = { kind = "Text", text = M.EMPTY_NOTE }
  end
  return { kind = "List", children = children }
end

-- End the held session, if any. Release is Core-idempotent and ungated, so a
-- revoked grant or an already-ended session still clears local state.
function M.close_overlay(reason)
  local handle = overlay_handle
  overlay_handle = nil
  if handle == nil then
    return false
  end
  local overlay = overlay_table()
  if overlay == nil or type(overlay.release) ~= "function" then
    return false
  end
  pcall(overlay.release, handle, reason or "cancelled")
  return true
end

local function acquire_overlay(overlay, source)
  if type(overlay.acquire) ~= "function" then
    return nil
  end
  local ok, handle = pcall(overlay.acquire, {
    title = scene_title(source),
    placeholder = M.SCENE_PLACEHOLDER,
  })
  if not ok or handle == nil then
    return nil
  end
  return handle
end

-- Present the outcome of one query. `ok` false closes any held surface so
-- stale rows never outlive a newer denial; `ok` true repaints the current
-- session or acquires one. Returns whether the scene was accepted.
function M.present(source, ok)
  if not ok then
    M.close_overlay("cancelled")
    return false
  end
  local overlay = overlay_table()
  if overlay == nil or type(overlay.update) ~= "function" then
    return false
  end
  local scene = M.build_scene(source, state.last_records, state.skipped_records)
  local handle = overlay_handle
  if handle == nil then
    handle = acquire_overlay(overlay, source)
    if handle == nil then
      return false
    end
    overlay_handle = handle
  end
  local updated_ok, updated = pcall(overlay.update, handle, scene)
  if updated_ok and updated ~= false then
    state.last_scene = scene
    return true
  end
  -- The Core ended the session (Esc, focus switch, idle timeout, unload) or
  -- rejected the update; a released handle can never be updated, so drop it
  -- and try one fresh surface before degrading to a data-only answer.
  M.close_overlay("cancelled")
  handle = acquire_overlay(overlay, source)
  if handle == nil then
    return false
  end
  overlay_handle = handle
  local retried_ok, retried = pcall(overlay.update, handle, scene)
  if not retried_ok or retried == false then
    M.close_overlay("cancelled")
    return false
  end
  state.last_scene = scene
  return true
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

  -- Every command answers with the typed `{ok, code}` table and paints the
  -- outcome into the focusable overlay. Presentation is guarded so a host
  -- without the surface, a missing grant, or a foreign capture can never turn
  -- a delivered page into a failed command (bitty#2967).
  local function run_query(source, args)
    local ok, code = M.query(source, args)
    pcall(M.present, source, ok)
    return { ok = ok, code = code }
  end

  bitty.commands.register({
    id = "query-transcript",
    title = "History: query transcript",
    description = "One-shot bounded snapshot over sealed transcript segments while opt-in capture holds; typed denial or a redacted labeled page painted into the focusable overlay.",
    args_schema = query_schema(),
    run = function(args)
      return run_query("transcript", args)
    end,
  })

  bitty.commands.register({
    id = "query-commands",
    title = "History: query commands",
    description = "One-shot scoped list, search, or tail read over command history; typed denial or a redacted labeled page painted into the focusable overlay.",
    args_schema = query_schema(),
    run = function(args)
      return run_query("commands", args)
    end,
  })

  bitty.commands.register({
    id = "query-kv",
    title = "History: query own KV",
    description = "One-shot snapshot read of the plugin own KV namespace only; cross-plugin reads are unrepresentable; the page is painted into the focusable overlay.",
    args_schema = query_schema(),
    run = function(args)
      return run_query("kv", args)
    end,
  })

  -- No event subscriptions: queries are snapshots, never streams. No
  -- keymap suggestions: history queries carry no chord vocabulary.
end

return M
