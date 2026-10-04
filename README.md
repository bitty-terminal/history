# history

W-137 S-3 (CTX-0003) Lua policy package for the Bitty history keeper:
opt-in history reads over the public host API only. Accepted contracts are
RFC-0004 (history-read surface, bitty-docs), W-131 (storage-and-history
boundary, bitty-docs), and W-137 (plugin history-and-storage policy,
bitty-plugins-docs); the SDK binding is bitty-plugin-sdk at `0a9487f`
(PR #144 head, OPEN — pinned derivation aid, not the accepted basis).

## Scope

- `bitty-plugin.toml`: plugin id `bitty-terminal.history`, version `0.0.1`,
  compat `bitty >=0.5,<1.0` with `plugin-api ^1.0`, exactly three
  capabilities (`history.transcript.read`, `history.commands.read`,
  `history.kv.read`), lazy `query-transcript`/`query-commands`/`query-kv`
  commands and no event subscriptions. No export capability: per the
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
  distinction, one-shot command dispatch, mismatch disable, denial parity
  vs a foreign manifest, and oracle-tight denial texts.

## Rules

- Public API only. No filesystem, process-spawn, network, clipboard,
  terminal-input, or selection-copy authority; reading authorizes delivery
  into the plugin VM only and export stays separately granted.
- Explicit scope and bound on every read: transcript/commands need a
  panel and/or workspace extent (never `*` or `all`), KV takes no extent;
  every query carries explicit `row_count`/`max_bytes` over zero.
  Over-bound requests deny; the plugin never clamps silently.
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
76fa42d6; SDK PR #144 pending (not basis). Opt-in bounded capture,
deletion/retention, privacy and recovery; Atuin through supported CLI/API
only. Do not treat OSC133 as command/cwd proof.

CTX-0001 -> CTX-0002 -> CTX-0003 -> CTX-0004 maps to Issues 4 -> 3 ->
2 -> 1. CTX-0001 (bootstrap) is complete and CTX-0002 (contract
readiness) is accepted; CTX-0003 implementation is this package, and
CTX-0004 independent verification is pending.
