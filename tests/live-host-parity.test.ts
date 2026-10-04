/**
 * Live-host parity for the history keeper (CTX-0004 verification evidence).
 *
 * Chain of evidence:
 * 1. Live Core: bitty @ 76fa42d6 (PR #1673, W-139 host surface) was exported
 *    read-only (`git archive`, never a checkout write) and its
 *    `HistoryGate` was driven through a 33-probe battery. The gate's own
 *    suite (25 tests) stayed green, and the battery output is committed as
 *    `tests/fixtures/live-host-matrix.json` with provenance.
 * 2. This suite replays every battery probe against the SDK MockHost (raw
 *    layer) and against the real `lua/history/init.lua` (plugin layer),
 *    asserting identical denial codes and identical success shapes.
 *
 * Two raw-layer shape differences are documented, not hidden (both deny;
 * neither leaks; both are unreachable through the plugin, which validates
 * client-side first):
 * - Scope construction (unscoped / wildcard / KV extents) and forbidden
 *   sources are `Disabled` diagnostics on live (no `E_` code) versus
 *   `E_DEF_INVALID` / `E_HISTORY_SCOPE_MISMATCH` throws on the mock. The
 *   plugin emits the mock-side codes before any host call, so the
 *   plugin-observable behavior is identical on both hosts.
 * - L3 with a standing grant: live denies `E_HISTORY_MISSING_GRANT` (the
 *   level passes the domain gate but the grant kind is wrong for L3) while
 *   the mock denies `E_HISTORY_TRUST_DENIED`. Both deny; the plugin never
 *   runs at L3 (Lua plugins are L1/L2 with standing grants).
 * - Grant-scope narrowing (query pane-b under a pane-a grant) is parked to
 *   Core W-146: live denies `E_HISTORY_SCOPE_MISMATCH`, the mock returns
 *   only the in-scope rows of its unscoped capability grant. Both keep
 *   foreign bytes out of unauthorized hands under their own grant model.
 */

import { afterEach, describe, expect, test } from "bun:test";

import { MockHost } from "bitty-plugin-sdk";

import matrix from "./fixtures/live-host-matrix.json";
import {
  activateHistory,
  HISTORY_CAPABILITIES,
  MANIFEST_SOURCE,
  type HistoryRun,
} from "./harness.js";

interface LiveOutcome {
  readonly status: string;
  readonly code?: string | null;
  readonly message?: string;
  readonly bodies?: readonly string[];
  readonly labels?: readonly string[];
  readonly redacted?: readonly boolean[];
  readonly truncated?: readonly boolean[];
  readonly seqs?: readonly number[];
  readonly total_in_scope?: number;
  readonly freshness?: string;
  readonly sequence?: readonly string[];
  readonly first?: LiveOutcome;
  readonly second?: LiveOutcome;
}

interface LiveProbe {
  readonly name: string;
  readonly outcome: LiveOutcome;
}

const PROBES = new Map<string, LiveOutcome>(
  (matrix.probes as LiveProbe[]).map((probe) => [probe.name, probe.outcome]),
);

function live(name: string): LiveOutcome {
  const outcome = PROBES.get(name);
  if (outcome === undefined) throw new Error(`live probe ${name} missing`);
  return outcome;
}

const runs: HistoryRun[] = [];

async function history(
  ...args: Parameters<typeof activateHistory>
): Promise<HistoryRun> {
  const run = await activateHistory(...args);
  runs.push(run);
  return run;
}

afterEach(() => {
  for (const run of runs.splice(0)) run.close();
});

/** Live seeds mirrored 1:1 (bodies are harness-redacted upstream). */
function seedLiveRows(host: MockHost): void {
  host.setHistoryCapture("transcript", true);
  host.setHistoryCapture("commands", true);
  host.setHistoryRows("transcript", [
    {
      panel: "pane-a",
      workspace: "ws-1",
      seq: 0,
      body: "redacted output line one",
    },
    {
      panel: "pane-a",
      workspace: "ws-1",
      seq: 1,
      body: "redacted output line two",
    },
    {
      panel: "pane-b",
      workspace: "ws-1",
      seq: 2,
      body: "foreign panel bytes never cross",
    },
    { panel: "pane-a", workspace: "ws-1", seq: 3, body: "s3cr3t-corpus-bytes" },
  ]);
  host.setHistoryRows("commands", [
    { panel: "pane-a", workspace: "ws-1", seq: 0, body: "make check" },
    { panel: "pane-a", workspace: "ws-1", seq: 1, body: "bun test" },
    { panel: "pane-a", workspace: "ws-1", seq: 2, body: "make lint" },
  ]);
  host.setHistoryRows("kv", [
    { owner: "bitty-terminal.history", seq: 0, body: "own state" },
    { owner: "example.foreign", seq: 1, body: "foreign state" },
  ]);
}

function scope(panel = "pane-a", workspace = "ws-1"): string {
  return `{panel="${panel}",workspace="${workspace}"}`;
}

/** Raw mock query returning the denial code (or "ok"). */
function mockCode(
  host: MockHost,
  source: "transcript" | "commands" | "kv",
  opts: Record<string, unknown>,
): string {
  try {
    (host.bitty.history[source] as { query: (o: unknown) => unknown }).query(
      opts,
    );
  } catch (error) {
    return String(error).match(/(E_[A-Z_]+)/)?.[1] ?? "E_UNKNOWN";
  }
  return "ok";
}

/** Raw mock query returning the success page. */
function mockPage(
  host: MockHost,
  source: "transcript" | "commands" | "kv",
  opts: Record<string, unknown>,
): {
  records: Array<{
    body: string;
    label: string;
    redacted: boolean;
    truncated: boolean;
    seq: number;
  }>;
  total_in_scope: number;
  freshness: string;
} {
  return (
    host.bitty.history[source] as { query: (o: unknown) => unknown }
  ).query(opts) as {
    records: Array<{
      body: string;
      label: string;
      redacted: boolean;
      truncated: boolean;
      seq: number;
    }>;
    total_in_scope: number;
    freshness: string;
  };
}

function grantedHost(
  options: {
    grants?: readonly string[];
    trustLevel?: string;
    safeMode?: boolean;
    seed?: boolean;
  } = {},
): MockHost {
  const host = new MockHost({
    manifestSource: MANIFEST_SOURCE,
    ...(options.trustLevel !== undefined
      ? { trustLevel: options.trustLevel }
      : {}),
    ...(options.safeMode !== undefined ? { safeMode: options.safeMode } : {}),
  });
  for (const capability of options.grants ?? HISTORY_CAPABILITIES) {
    host.grant(capability);
  }
  host.beginActivation();
  host.endActivation();
  if (options.seed !== false) seedLiveRows(host);
  return host;
}

describe("provenance and taxonomy", () => {
  test("fixture provenance names the live Core commit and surface", () => {
    expect(matrix.provenance.core_commit).toBe("76fa42d6");
    expect(matrix.provenance.core_pr).toBe(1673);
    expect(matrix.provenance.surface).toBe("history_read.rs");
  });

  test("the eight denial codes match the live taxonomy exactly", () => {
    expect(matrix.provenance.denial_codes).toEqual([
      "E_HISTORY_MISSING_GRANT",
      "E_HISTORY_REVOKED_GRANT",
      "E_HISTORY_SCOPE_MISMATCH",
      "E_HISTORY_OVER_BOUND",
      "E_HISTORY_CAPTURE_DISABLED",
      "E_HISTORY_SAFE_MODE",
      "E_HISTORY_TRUST_DENIED",
      "E_HISTORY_UNAVAILABLE",
    ]);
  });

  test("fixture caps equal the plugin bounds and the mock limits", () => {
    expect(matrix.provenance.caps).toEqual({
      max_rows_per_query: 16,
      max_bytes_per_query: 4096,
      max_bytes_per_row: 256,
      max_queries_per_window: 4,
      max_bytes_per_window: 8192,
    });
    expect(matrix.provenance.label).toBe("untrusted-observation");
  });
});

describe("denied-with-code parity (mock raw layer vs live gate)", () => {
  test("missing, revoked, and isolated grants deny identically", () => {
    for (const [probe, grants] of [
      ["missing-grant", []],
      ["source-isolation", ["history.transcript.read"]],
    ] as Array<[string, readonly string[]]>) {
      const expected = live(probe).code;
      const host = grantedHost({ grants });
      const source = probe === "source-isolation" ? "commands" : "transcript";
      expect(
        mockCode(host, source, {
          scope: { panel: "pane-a", workspace: "ws-1" },
          row_count: 4,
          max_bytes: 4096,
          op: "list",
        }),
      ).toBe(expected);
      host.dispose();
    }
    const revoked = grantedHost({});
    revoked.revoke("history.transcript.read");
    expect(
      mockCode(revoked, "transcript", {
        scope: { panel: "pane-a", workspace: "ws-1" },
        row_count: 4,
        max_bytes: 4096,
        op: "list",
      }),
    ).toBe(live("revoked-grant").code);
    revoked.dispose();
  });

  test("over-bound, empty-needle, capture-off, purged, and safe-mode deny identically", () => {
    const cases: Array<{
      probe: string;
      source: "transcript" | "commands" | "kv";
      opts: Record<string, unknown>;
      capture?: boolean;
      safeMode?: boolean;
    }> = [
      {
        probe: "over-rows",
        source: "transcript",
        opts: {
          scope: { panel: "pane-a", workspace: "ws-1" },
          row_count: 17,
          max_bytes: 4096,
          op: "list",
        },
      },
      {
        probe: "over-bytes",
        source: "transcript",
        opts: {
          scope: { panel: "pane-a", workspace: "ws-1" },
          row_count: 4,
          max_bytes: 5000,
          op: "list",
        },
      },
      {
        probe: "zero-rows",
        source: "transcript",
        opts: {
          scope: { panel: "pane-a", workspace: "ws-1" },
          row_count: 0,
          max_bytes: 4096,
          op: "list",
        },
      },
      {
        probe: "zero-bytes",
        source: "transcript",
        opts: {
          scope: { panel: "pane-a", workspace: "ws-1" },
          row_count: 4,
          max_bytes: 0,
          op: "list",
        },
      },
      {
        probe: "empty-needle",
        source: "transcript",
        opts: {
          scope: { panel: "pane-a", workspace: "ws-1" },
          row_count: 4,
          max_bytes: 4096,
          op: "search",
        },
      },
      {
        probe: "capture-disabled",
        source: "transcript",
        opts: {
          scope: { panel: "pane-a", workspace: "ws-1" },
          row_count: 4,
          max_bytes: 4096,
          op: "list",
        },
        capture: false,
      },
      {
        probe: "safe-mode",
        source: "transcript",
        opts: {
          scope: { panel: "pane-a", workspace: "ws-1" },
          row_count: 4,
          max_bytes: 4096,
          op: "list",
        },
        safeMode: true,
      },
    ];
    for (const c of cases) {
      const host = grantedHost({ safeMode: c.safeMode });
      if (c.capture === false) host.setHistoryCapture("transcript", false);
      expect(mockCode(host, c.source, c.opts)).toBe(live(c.probe).code);
      host.dispose();
    }
    // Purged-only range: typed unavailability on both hosts.
    const purged = grantedHost({ seed: false });
    purged.setHistoryCapture("transcript", true);
    purged.setHistoryRows("transcript", [
      {
        panel: "pane-a",
        workspace: "ws-1",
        seq: 0,
        body: "expired bytes",
        purged: true,
      },
    ]);
    expect(
      mockCode(purged, "transcript", {
        scope: { panel: "pane-a", workspace: "ws-1" },
        row_count: 4,
        max_bytes: 4096,
        op: "list",
      }),
    ).toBe(live("purged-list").code);
    // Purged search: empty page on both hosts, never an oracle signal.
    const page = mockPage(purged, "transcript", {
      scope: { panel: "pane-a", workspace: "ws-1" },
      row_count: 4,
      max_bytes: 4096,
      op: "search",
      needle: "expired",
    });
    expect(page.records).toEqual([]);
    expect(
      live("purged-search").outcome ?? live("purged-search"),
    ).toBeDefined();
    expect(live("purged-search").bodies).toEqual([]);
    purged.dispose();
  });

  test("L4 trust denies identically; L3-standing divergence is recorded", () => {
    const l4 = grantedHost({ trustLevel: "L4" });
    expect(
      mockCode(l4, "transcript", {
        scope: { panel: "pane-a", workspace: "ws-1" },
        row_count: 4,
        max_bytes: 4096,
        op: "list",
      }),
    ).toBe(live("trust-l4").code);
    l4.dispose();
    // Documented divergence: live admits L3 past the domain gate and then
    // denies the wrong-kind standing grant as missing-grant; the mock denies
    // L3 at the trust gate. Both deny; the plugin never runs at L3.
    const l3 = grantedHost({ trustLevel: "L3" });
    expect(
      mockCode(l3, "transcript", {
        scope: { panel: "pane-a", workspace: "ws-1" },
        row_count: 4,
        max_bytes: 4096,
        op: "list",
      }),
    ).toBe("E_HISTORY_TRUST_DENIED");
    expect(live("trust-l3-standing").code).toBe("E_HISTORY_MISSING_GRANT");
    l3.dispose();
  });

  test("window budget exhausts after four successes on both hosts", () => {
    expect(live("window-budget").sequence).toEqual([
      "ok",
      "ok",
      "ok",
      "ok",
      "E_HISTORY_OVER_BOUND",
    ]);
    const host = grantedHost({});
    const opts = {
      scope: { panel: "pane-a", workspace: "ws-1" },
      row_count: 4,
      max_bytes: 4096,
      op: "list",
    };
    const seen: string[] = [];
    for (let i = 0; i < 5; i += 1)
      seen.push(mockCode(host, "transcript", opts));
    expect(seen).toEqual(["ok", "ok", "ok", "ok", "E_HISTORY_OVER_BOUND"]);
    host.dispose();
  });
});

describe("disabled-diagnostic paths (live shape vs plugin-observable codes)", () => {
  test("live scope-construction failures carry no E_ code and name no content", () => {
    for (const probe of [
      "unscoped-scope",
      "wildcard-scope",
      "kv-extent-scope",
    ]) {
      const outcome = live(probe);
      expect(outcome.status).toBe("disabled");
      expect(outcome.code).toBeNull();
      expect(outcome.message).not.toMatch(/E_[A-Z_]+/);
      expect(outcome.message).not.toMatch(/s3cr3t-corpus-bytes/);
      expect(outcome.message).not.toMatch(/foreign-panel-bytes/);
    }
    for (const probe of [
      "forbidden-session",
      "forbidden-snapshot",
      "forbidden-session-snapshot",
      "forbidden-nope",
    ]) {
      const outcome = live(probe);
      expect(outcome.status).toBe("disabled");
      expect(outcome.message).toMatch(/Core-only/);
    }
    expect(live("version-mismatch").status).toBe("disabled");
  });

  test("the plugin blocks those paths client-side with the mock-side codes", async () => {
    const run = await history();
    run.host.setHistoryCapture("transcript", true);
    async function lua(source: string, opts: string): Promise<boolean> {
      return (await run.lua.doString(
        `return history.query("${source}", ${opts})`,
      )) as boolean;
    }
    async function code(): Promise<string> {
      return (await run.query("history.last_code()")) as string;
    }
    expect(
      await lua(
        "transcript",
        `{scope={},row_count=4,max_bytes=4096,op="list"}`,
      ),
    ).toBe(false);
    expect(await code()).toBe("E_HISTORY_SCOPE_MISMATCH");
    expect(
      await lua(
        "transcript",
        `{scope={panel="*",workspace="ws-1"},row_count=4,max_bytes=4096,op="list"}`,
      ),
    ).toBe(false);
    expect(await code()).toBe("E_DEF_INVALID");
    expect(
      await lua(
        "kv",
        `{scope=${scope()},row_count=4,max_bytes=4096,op="list"}`,
      ),
    ).toBe(false);
    expect(await code()).toBe("E_DEF_INVALID");
    for (const source of ["session", "snapshot", "session-snapshot", "nope"]) {
      expect(
        await lua(
          source,
          `{scope=${scope()},row_count=4,max_bytes=4096,op="list"}`,
        ),
      ).toBe(false);
      expect(await code()).toBe("E_DEF_INVALID");
    }
    // Mock raw layer agrees with the plugin on every one of these codes.
    const raw = grantedHost({});
    expect(
      mockCode(raw, "transcript", {
        scope: {},
        row_count: 4,
        max_bytes: 4096,
        op: "list",
      }),
    ).toBe("E_HISTORY_SCOPE_MISMATCH");
    expect(
      mockCode(raw, "transcript", {
        scope: { panel: "*", workspace: "ws-1" },
        row_count: 4,
        max_bytes: 4096,
        op: "list",
      }),
    ).toBe("E_DEF_INVALID");
    expect(
      mockCode(raw, "kv", {
        scope: { panel: "pane-a" },
        row_count: 4,
        max_bytes: 4096,
        op: "list",
      }),
    ).toBe("E_DEF_INVALID");
    raw.dispose();
  });
});

describe("success-shape parity (identical seeds, grants, and capture)", () => {
  test("transcript list returns the same redacted labeled page", () => {
    const expected = live("transcript-list");
    const host = grantedHost({});
    const page = mockPage(host, "transcript", {
      scope: { panel: "pane-a", workspace: "ws-1" },
      row_count: 4,
      max_bytes: 4096,
      op: "list",
    });
    // In-scope redacted content is delivered on success by design (the
    // secret row below is in-scope pane-a content, already redacted
    // upstream); denials are what must never carry content bytes.
    expect(page.records.map((r) => r.body)).toEqual(expected.bodies);
    expect(page.records.map((r) => r.label)).toEqual(expected.labels);
    expect(page.records.map((r) => r.redacted)).toEqual(expected.redacted);
    expect(page.records.map((r) => r.truncated)).toEqual(expected.truncated);
    expect(page.records.map((r) => r.seq)).toEqual(expected.seqs);
    expect(page.total_in_scope).toBe(expected.total_in_scope);
    expect(page.freshness).toBe("point-in-time-no-guarantee");
    host.dispose();
  });

  test("commands tail and search match the live pages", () => {
    const host = grantedHost({});
    const tail = mockPage(host, "commands", {
      scope: { panel: "pane-a", workspace: "ws-1" },
      row_count: 2,
      max_bytes: 4096,
      op: "tail",
    });
    expect(tail.records.map((r) => r.body)).toEqual(
      live("commands-tail").bodies,
    );
    expect(tail.total_in_scope).toBe(live("commands-tail").total_in_scope);
    const search = mockPage(host, "commands", {
      scope: { panel: "pane-a", workspace: "ws-1" },
      row_count: 4,
      max_bytes: 4096,
      op: "search",
      needle: "make",
    });
    expect(search.records.map((r) => r.body)).toEqual(
      live("commands-search-make").bodies,
    );
    host.dispose();
  });

  test("kv returns only the caller namespace on both hosts", () => {
    const expected = live("kv-list");
    const host = grantedHost({});
    const page = mockPage(host, "kv", {
      row_count: 4,
      max_bytes: 4096,
      op: "list",
    });
    expect(page.records.map((r) => r.body)).toEqual(expected.bodies);
    expect(page.total_in_scope).toBe(expected.total_in_scope);
    host.dispose();
  });

  test("truncation lands on the same char boundary with the label intact", () => {
    const expected = live("truncation");
    const host = grantedHost({ seed: false });
    host.setHistoryCapture("transcript", true);
    host.setHistoryRows("transcript", [
      { panel: "pane-a", workspace: "ws-1", seq: 0, body: "é".repeat(200) },
    ]);
    const page = mockPage(host, "transcript", {
      scope: { panel: "pane-a", workspace: "ws-1" },
      row_count: 4,
      max_bytes: 4096,
      op: "list",
    });
    expect(page.records).toHaveLength(1);
    expect(page.records[0]?.body).toBe(expected.bodies?.[0]);
    expect(page.records[0]?.truncated).toBe(true);
    expect(page.records[0]?.label).toBe("untrusted-observation");
    expect(page.records[0]?.redacted).toBe(true);
    host.dispose();
  });
});

describe("plugin end-to-end over the live battery seeds", () => {
  test("the real entry point reproduces the live transcript page", async () => {
    const run = await history();
    seedLiveRows(run.host);
    const ok = (await run.lua.doString(
      `return history.query("transcript", {scope=${scope()},row_count=4,max_bytes=4096,op="list"})`,
    )) as boolean;
    expect(ok).toBe(true);
    const count = (await run.query("history.record_count()")) as number;
    expect(count).toBe(live("transcript-list").total_in_scope);
    const first = (await run.query("history.record_body(1)")) as string;
    expect(first).toBe(live("transcript-list").bodies?.[0]);
    const label = (await run.query("history.record_label(1)")) as string;
    expect(label).toBe("untrusted-observation");
  });

  test("the real entry point reproduces the live kv isolation page", async () => {
    const run = await history();
    seedLiveRows(run.host);
    const ok = (await run.lua.doString(
      `return history.query("kv", {row_count=4,max_bytes=4096,op="list"})`,
    )) as boolean;
    expect(ok).toBe(true);
    expect((await run.query("history.record_count()")) as number).toBe(
      live("kv-list").total_in_scope,
    );
    expect((await run.query("history.record_body(1)")) as string).toBe(
      live("kv-list").bodies?.[0],
    );
  });

  test("denial codes through the plugin equal the live codes", async () => {
    const run = await history({ grants: [] });
    const denied = (await run.lua.doString(
      `return history.query("transcript", {scope=${scope()},row_count=4,max_bytes=4096,op="list"})`,
    )) as boolean;
    expect(denied).toBe(false);
    expect((await run.query("history.last_code()")) as string).toBe(
      live("missing-grant").code,
    );
  });
});

describe("oracle-tight denial texts on both hosts", () => {
  test("no live denial message leaks content, foreign ids, or counts", () => {
    const denied = (matrix.probes as LiveProbe[])
      .map((probe) => probe.outcome)
      .filter((outcome) => outcome.status === "denied");
    expect(denied.length).toBeGreaterThan(0);
    for (const outcome of denied) {
      expect(outcome.message).not.toMatch(/s3cr3t-corpus-bytes/);
      expect(outcome.message).not.toMatch(/foreign-panel-bytes/);
      expect(outcome.message).not.toMatch(/foreign state/);
      expect(outcome.message).not.toMatch(/pane-b/);
      expect(outcome.message).toMatch(/E_HISTORY_/);
    }
  });

  test("no mock denial text leaks content or foreign ids either", () => {
    const host = grantedHost({ grants: [] });
    const texts: string[] = [];
    for (const opts of [
      {
        scope: { panel: "pane-a", workspace: "ws-1" },
        row_count: 4,
        max_bytes: 4096,
        op: "list",
      },
      { scope: {}, row_count: 4, max_bytes: 4096, op: "list" },
      {
        scope: { panel: "*", workspace: "ws-1" },
        row_count: 4,
        max_bytes: 4096,
        op: "list",
      },
      {
        scope: { panel: "pane-a", workspace: "ws-1" },
        row_count: 99,
        max_bytes: 4096,
        op: "list",
      },
    ]) {
      try {
        (
          host.bitty.history.transcript as { query: (o: unknown) => unknown }
        ).query(opts);
      } catch (error) {
        texts.push(String(error));
      }
    }
    expect(texts.length).toBeGreaterThan(0);
    for (const text of texts) {
      expect(text).not.toMatch(/s3cr3t-corpus-bytes/);
      expect(text).not.toMatch(/foreign-panel-bytes/);
      expect(text).not.toMatch(/pane-b/);
    }
    host.dispose();
  });
});
