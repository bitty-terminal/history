# History

W-137 S-3 (CTX-0003) Lua policy package for the Bitty history keeper:
opt-in history reads over the public host API only. Accepted contracts are
RFC-0004 (history-read surface, bitty-docs), W-131 (storage-and-history
boundary, bitty-docs), and W-137 (plugin history-and-storage policy,
bitty-plugins-docs); the SDK binding is bitty-plugin-sdk at `3ea8e58`
(merged `main`: history surface from PR #144, declared-settings support from
PR #152).

## Overview

History answers bounded, read-only snapshot queries over Bitty's persisted
history: sealed transcript segments, command history, and the plugin's own
key-value namespace. Every answer is redacted, truncated, attributed, and
labeled `untrusted-observation`, or replaced by a typed denial. The plugin
never streams, holds no cursor across calls, and never reads session
snapshots.

## Install

Prerequisites:

- Bitty `>=0.0.24,<0.1` with Plugin API `^1.0` (the manifest `[compat]`
  range).
- Opt-in capture enabled for the sources you query. Transcript and command
  history return nothing when capture is off (`E_HISTORY_CAPTURE_DISABLED`).
- Consent to the three read grants: `history.transcript.read`,
  `history.commands.read`, and `history.kv.read`. The plugin has no export
  authority, so reading never implies clipboard, filesystem, or process
  access.

Install from a local checkout:

```sh
git clone https://github.com/bitty-terminal/history.git
cd history
bitty plugin install "$PWD"
bitty plugin enable bitty-terminal.history
bitty plugin list
```

`bitty plugin install <path>` stages the package under the XDG data store and
records the capabilities you consent to; it executes no plugin code
(`--yes` approves non-interactively). Verify activation with
`bitty plugin list`: the entry must show `bitty-terminal.history`, version
`0.0.1`, source `local-path`, enabled, and the three read grants.
`bitty plugin info bitty-terminal.history` prints the recorded grant set.

## Commands

Every command id is qualified with the plugin id. All commands return a table
with `ok` and `code`; on success the bounded page is delivered through the
host, and on denial `code` carries the typed error. None of the commands has a
default keybinding.

| Command                                   | What it does                                                                                        | Arguments                                                                                                                                                                                                                           | Default keybinding |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ |
| `bitty-terminal.history:query-transcript` | One bounded snapshot over sealed transcript segments while opt-in capture holds.                    | `scope` (`panel` and/or `workspace`), `row_start` (integer ≥ 0), `row_count` (integer ≥ 1, cap 16), `max_bytes` (integer ≥ 1, cap 4096), `op` (`list` default, `tail`, or `search`), `needle` (1–256 bytes, required for `search`). | None               |
| `bitty-terminal.history:query-commands`   | One bounded list, tail, or search read over command history.                                        | Same as `query-transcript`.                                                                                                                                                                                                         | None               |
| `bitty-terminal.history:query-kv`         | One bounded snapshot read of the plugin's own KV namespace; cross-plugin reads are unrepresentable. | `row_start`, `row_count` (cap 16), `max_bytes` (cap 4096), `op`, `needle`. No panel or workspace extent: the caller namespace is the scope.                                                                                         | None               |

Explicit arguments always win. An argument-free dispatch (a keybinding or
palette invocation carrying `{}`) resolves the bounded defaults from
Configuration; with no usable scope axis it denies with
`E_HISTORY_SCOPE_MISMATCH` rather than widening the query.

## Configuration

Settings live in `$XDG_CONFIG_HOME/bitty/plugins/bitty-terminal.history.lua`.
Values are read at activation and pinned to that plugin generation.

| Key                 | Type     | Default | Description                                                                                                                                                               | Reload  |
| ------------------- | -------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `default_panel`     | `string` | `""`    | Panel id used as the default scope axis when a dispatch carries no explicit scope. Empty means unset; wildcard, blank, control, or over-long ids fail as `E_DEF_INVALID`. | Restart |
| `default_workspace` | `string` | `""`    | Workspace id used as the default scope axis when a dispatch carries no explicit scope. Empty means unset; the same validation applies.                                    | Restart |
| `row_count`         | `int`    | `16`    | Rows requested when a dispatch carries no explicit `row_count`. Accepted 1–16; an out-of-window value falls back to the shipped cap (16).                                 | Restart |
| `max_bytes`         | `int`    | `4096`  | Byte budget when a dispatch carries no explicit `max_bytes`. Accepted 1–4096; an out-of-window value falls back to the shipped cap (4096).                                | Restart |

Example:

```lua
-- $XDG_CONFIG_HOME/bitty/plugins/bitty-terminal.history.lua
return {
  default_panel = "", -- set to a panel id for argument-free dispatch
  default_workspace = "",
  row_count = 16,
  max_bytes = 4096,
}
```

`Restart` means settings are resolved during activation: there is no settings
watcher or hot-reload path, so edit the file and restart Bitty. Explicit
`scope`, `row_count`, and `max_bytes` arguments override these values.
Configured values are convenience defaults, never authority: the host still
intersects every query scope with the granted scope and denies over-bound
requests.

## Keybindings

History registers no default keybindings. Bind a chord in
`$XDG_CONFIG_HOME/bitty/init.lua`:

```lua
return {
  keymaps = {
    {
      chord = "ctrl+shift+h",
      action = "bitty-terminal.history:query-transcript",
      context = "global",
    },
  },
}
```

An argument-free binding uses the Configuration defaults above. To query a
specific panel or workspace, bind the command through a caller that passes
`scope` explicitly.

## Troubleshooting

| Code                         | Class        | Cause                                                                                                               | Remedy                                                                                                                                             |
| ---------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `E_SETTINGS_UNDECLARED`      | `validation` | A settings read named a key absent from the manifest `[settings]` declarations.                                     | Install a plugin version whose declarations match the running build. Only the four keys above are declared; undeclared config entries are ignored. |
| `E_INCOMPATIBLE`             | `validation` | The running host is outside `>=0.0.24,<0.1`, or Plugin API is not `^1.0`.                                           | Upgrade Bitty or install a History release whose `[compat]` range covers your host.                                                                |
| `E_CAPABILITY_DENIED`        | `runtime`    | A required read grant is missing, expired, or revoked.                                                              | Re-run `bitty plugin install <path>` and approve the current grant set; `bitty plugin list` shows what is recorded.                                |
| `E_HISTORY_MISSING_GRANT`    | `runtime`    | No per-plugin, per-source read grant is recorded (deny by default).                                                 | Approve the matching `history.*.read` grant for the source you query.                                                                              |
| `E_HISTORY_REVOKED_GRANT`    | `runtime`    | The grant existed but was revoked or expired after activation.                                                      | Re-grant it and restart Bitty; a live generation keeps the grant bound at activation.                                                              |
| `E_HISTORY_SCOPE_MISMATCH`   | `runtime`    | The query names no panel/workspace extent, the grant does not cover it, or no usable default context is configured. | Pass an explicit `scope`, or set `default_panel`/`default_workspace` and restart. The host only returns data inside the granted scope.             |
| `E_HISTORY_OVER_BOUND`       | `runtime`    | `row_count`, `max_bytes`, or the needle exceeds the accepted cap, or a bound is zero.                               | Stay inside 1–16 rows, 1–4096 bytes, and a 1–256 byte needle. The plugin never clamps an explicit over-bound request.                              |
| `E_HISTORY_CAPTURE_DISABLED` | `runtime`    | Opt-in capture for the source is off, so nothing was persisted to read.                                             | Enable capture for transcript or command history, then query again.                                                                                |
| `E_HISTORY_SAFE_MODE`        | `runtime`    | Bitty runs in safe mode, which reads no transcript, history, snapshot, or KV.                                       | Restart without safe mode to use History.                                                                                                          |
| `E_HISTORY_TRUST_DENIED`     | `runtime`    | The caller's trust level or domain admits no standing access.                                                       | Query from a trusted local context; unknown trust levels and domains deny rather than default.                                                     |
| `E_HISTORY_UNAVAILABLE`      | `runtime`    | The content was purged or expired, or the source is otherwise unavailable.                                          | Treat it as typed unavailability, not an empty result. Query a narrower point in time or accept that the data is gone.                             |
| `E_DEF_INVALID`              | `validation` | A configured default scope is wildcard, blank, control-bearing, or longer than 128 bytes.                           | Fix `default_panel` or `default_workspace` and restart. Empty string means "no bound context", not a wildcard.                                     |

`E_DISABLED` means the activation-time compatibility gate rejected this
generation, and `NO_HOST` means the module was loaded without the host bridge
for tests or headless use; neither state exposes commands.

## Scope

- `bitty-plugin.toml`: plugin id `bitty-terminal.history`, version `0.0.1`,
  compat `bitty >=0.0.24,<0.1` with `plugin-api ^1.0`, exactly three
  capabilities (`history.transcript.read`, `history.commands.read`,
  `history.kv.read`), lazy `query-transcript`/`query-commands`/`query-kv`
  commands, no event subscriptions, and four declared settings
  (`default_panel`, `default_workspace`, `row_count`, `max_bytes`) that supply
  capability-neutral bounded defaults. No export capability: per the
  RFC-0004 grant-combination rule the history grant never implies
  clipboard, filesystem, or process authority.
- `lua/history/init.lua`: the whole policy. Source/scope/bound validation
  (transcript, commands, own KV; session snapshots fail closed), one-shot
  bounded snapshot queries through `bitty.history.*.query`, typed-denial
  surfacing with oracle-tight shapes, and untrusted-label verification on
  every delivered page (redacted, labeled, attributed, point-in-time).
  No streaming, no watch, no tail-follow; no session-snapshot access.
- `tests/`: bun + wasmoon suite against the SDK `MockHost`, mirroring the
  composer harness pattern. Covers scoped snapshots with typed denials,
  source isolation, tail/search ops, over-bound denials, purge/expiry as
  typed unavailability, safe-mode and trust denials, revoked-vs-missing
  distinction, one-shot command dispatch, argument-free keybinding dispatch
  with bounded defaults (explicit-scope precedence and the no-context
  denial), mismatch disable, denial parity vs a foreign manifest, and
  oracle-tight denial texts.

## Rules

- Public API only. No filesystem, process-spawn, network, clipboard,
  terminal-input, or selection-copy authority; reading authorizes delivery
  into the plugin VM only and export stays separately granted.
- Explicit scope and bound on every read: transcript/commands need a
  panel and/or workspace extent (never `*` or `all`), KV takes no extent;
  every query carries explicit `row_count`/`max_bytes` over zero.
  Over-bound requests deny; the plugin never clamps silently.
- Argument-free dispatch (a keybinding or palette invocation carrying `{}`)
  resolves a bounded default instead of failing. Explicit `scope`,
  `row_count`, and `max_bytes` always win unchanged. When they are absent the
  plugin reads the declared settings context: `default_panel` /
  `default_workspace` (empty string means unset; wildcard, blank, control, or
  over-long ids fail closed as `E_DEF_INVALID`) and `row_count` /
  `max_bytes` (accepted only inside the 1..16 / 1..4096 caps; an out-of-window
  configured value falls back to the shipped cap). With no valid scope axis
  the query still denies with `E_HISTORY_SCOPE_MISMATCH`. The public Lua
  surface exposes no focus getter, so the plugin never reads
  `bitty.workspace`/`bitty.panel` and never widens its capability set to
  resolve one; the host remains authoritative and still intersects every
  query scope with the granted scope.
- Records are redacted and truncated with attribution and the
  Core-attached `untrusted-observation` label: bodies are content under the
  prompt-injection rule, never instructions, never routed into an
  instruction channel.
- Purges and expiry are respected: purged content surfaces as typed
  unavailability, never as a silent gap and never resurrected from a
  derived index.
- Version/capability mismatch disables with a diagnostic and no partial
  activation: no commands exist for the generation.
- Bounds mirror the accepted shape (16 rows / 4096 bytes per query,
  256 bytes per row, 1..256 byte needles, 1..128 byte scope ids): the shape
  is normative, exact numbers stay parked to W-137/W-139/W-146.

## Non-goals (S-3 only)

- No Core changes, no host-API implementation, no SDK changes.
- No registry onboarding and no release; the package stays a candidate until
  CTX-0004 independently verifies privacy, retention, quota, and parity
  evidence.
- No second read channel: the plugin registers no event subscription and
  holds no cursor across calls; a caller that wants newer state issues a
  new bounded query under its grant.

## Compat

The host validates `plugin-api ^1.0` before activation and fails closed on
mismatch. The plugin repeats the major-version gate at load as
defense in depth: on mismatch it records `disabled_reason` and registers
nothing for the generation.

## Prerequisites

RFC-0004 accepted + threat-model 48b60c4 + W-131 accepted (bitty-docs
21d63dc) + W-137 accepted (bitty-plugins-docs 002c7ce) + Core host
76fa42d6; SDK `3ea8e58` (merged `main`, history + declared settings).
Opt-in bounded capture, deletion/retention, privacy and recovery; Atuin
through supported CLI/API only. Do not treat OSC133 as command/cwd proof.

CTX-0001 -> CTX-0002 -> CTX-0003 -> CTX-0004 maps to Issues 4 -> 3 ->
2 -> 1. CTX-0001 (bootstrap) is complete, CTX-0002 (contract readiness) is
accepted, CTX-0003 implementation is this package, and CTX-0004
independent verification is recorded; CTX-0005 adds the bounded default
context for argument-free dispatch.

## Development

Run the repository gates through the justfile:

```sh
just install
just check
```

`just check` includes `just docs-check`, which fails when the README
Configuration table omits a declared `[settings]` key, documents an undeclared
key, or drifts from the declared type or default.
