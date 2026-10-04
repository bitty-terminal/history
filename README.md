# history

Metadata-only official history plugin candidate; no manifest or Lua code, not onboarded. Read [AGENTS](AGENTS.md) and [TODO](TODO.md).

Prerequisites: RFC-0004 accepted + threat-model 48b60c4 + W-131 accepted (bitty-docs 21d63dc) + W-137 accepted (bitty-plugins-docs 002c7ce) + Core host 76fa42d6; SDK PR #144 pending (not basis). Opt-in bounded capture, deletion/retention, privacy and recovery; Atuin through supported CLI/API only. Do not treat OSC133 as command/cwd proof.

CTX-0001 -> CTX-0002 -> CTX-0003 -> CTX-0004 maps to Issues #4 -> #3 -> #2 -> #1. CTX-0001 (bootstrap) is complete: metadata gates, independent review, first publication, redacted CarryCtx snapshot and branch protection are recorded. CTX-0002 (contract readiness) is accepted on the RFC-0004/W-131/W-137 acceptances plus threat-model and Core host; CTX-0003 implementation is authorized. No product implementation is landed.
