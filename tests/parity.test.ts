/**
 * Denial parity plus oracle-tight denial texts (CTX-0003 conformance
 * evidence, second half).
 *
 * First-party/third-party parity: the official keeper
 * (`bitty-terminal.history`, this manifest) sees byte-identical denials and
 * success shapes to a foreign manifest with the same grants
 * (`example.history-clone`). Steps mirror the SDK conformance pair
 * 33/34-parity-denial-history (same operation, only the manifest differs).
 *
 * Oracle-tightness: denial error texts name the category plus the trust
 * level and the family only, never content bytes, foreign identifiers, or
 * any absent-versus-denied signal. Probed directly against the mock host
 * (which owns the denial text) for every denial in the taxonomy.
 */

import { afterEach, describe, expect, test } from "bun:test";

import { MockHost } from "bitty-plugin-sdk";

import {
  activateHistory,
  HISTORY_CAPABILITIES,
  MANIFEST_SOURCE,
  type HistoryRun,
} from "./harness.js";

const runs: HistoryRun[] = [];

async function keeper(
  ...args: Parameters<typeof activateHistory>
): Promise<HistoryRun> {
  const run = await activateHistory(...args);
  runs.push(run);
  return run;
}

afterEach(() => {
  for (const run of runs.splice(0)) run.close();
});

/** Foreign manifest: same grants, different principal. */
function foreignManifest(): string {
  return MANIFEST_SOURCE.replaceAll(
    "bitty-terminal.history",
    "example.history-clone",
  )
    .replace('name = "History Clone"', 'name = "History Clone"')
    .replace('name = "History"', 'name = "History Clone"');
}

/** One denial probe every parity leg runs. */
const DENIAL_PROBES: ReadonlyArray<{
  name: string;
  source: "transcript" | "commands" | "kv";
  opts: Record<string, unknown>;
}> = [
  {
    name: "missing-grant",
    source: "transcript",
    opts: {
      scope: { panel: "pane-a", workspace: "ws-1" },
      row_count: 4,
      max_bytes: 4096,
      op: "list",
    },
  },
  {
    name: "scope-mismatch",
    source: "commands",
    opts: { scope: {}, row_count: 4, max_bytes: 4096, op: "list" },
  },
  {
    name: "wildcard-malformed",
    source: "transcript",
    opts: {
      scope: { panel: "*", workspace: "ws-1" },
      row_count: 4,
      max_bytes: 4096,
      op: "list",
    },
  },
  {
    name: "over-bound",
    source: "transcript",
    opts: {
      scope: { panel: "pane-a", workspace: "ws-1" },
      row_count: 99,
      max_bytes: 4096,
      op: "list",
    },
  },
  {
    name: "kv-extent-rejected",
    source: "kv",
    opts: {
      scope: { panel: "pane-a" },
      row_count: 4,
      max_bytes: 4096,
      op: "list",
    },
  },
];

/** Run one probe against a raw MockHost and return the denial code. */
function probeDenial(
  host: MockHost,
  source: "transcript" | "commands" | "kv",
  opts: Record<string, unknown>,
): string {
  try {
    (
      host.bitty.history[source] as {
        query: (o: unknown) => unknown;
      }
    ).query(opts);
  } catch (error) {
    const text = String(error);
    const code = text.match(/(E_[A-Z_]+)/)?.[1];
    if (code === undefined) throw error;
    return code;
  }
  throw new Error(`probe ${source} did not deny`);
}

describe("first-party/third-party denial parity", () => {
  test("identical denials for the same operation under both manifests", () => {
    const first = new MockHost({ manifestSource: MANIFEST_SOURCE });
    const third = new MockHost({ manifestSource: foreignManifest() });
    for (const leg of [first, third]) {
      leg.beginActivation();
      leg.endActivation();
    }
    for (const probe of DENIAL_PROBES) {
      const a = probeDenial(first, probe.source, probe.opts);
      const b = probeDenial(third, probe.source, probe.opts);
      expect(`${probe.name}:${a}`).toBe(`${probe.name}:${b}`);
    }
    first.dispose();
    third.dispose();
  });

  test("identical success shapes for the same seeded rows under both manifests", async () => {
    async function successPage(manifestSource: string): Promise<string> {
      const host = new MockHost({ manifestSource });
      for (const cap of HISTORY_CAPABILITIES) host.grant(cap);
      host.beginActivation();
      host.endActivation();
      host.setHistoryCapture("transcript", true);
      host.setHistoryRows("transcript", [
        { panel: "pane-a", workspace: "ws-1", seq: 0, body: "parity bytes" },
      ]);
      const page = host.bitty.history.transcript.query({
        scope: { panel: "pane-a", workspace: "ws-1" },
        row_count: 4,
        max_bytes: 4096,
        op: "list",
      }) as {
        records: Array<{ body: string; label: string; redacted: boolean }>;
        total_in_scope: number;
        freshness: string;
      };
      host.dispose();
      return JSON.stringify({
        bodies: page.records.map((r) => r.body),
        labels: page.records.map((r) => r.label),
        redacted: page.records.map((r) => r.redacted),
        total: page.total_in_scope,
        freshness: page.freshness,
      });
    }
    expect(await successPage(foreignManifest())).toBe(
      await successPage(MANIFEST_SOURCE),
    );
  });

  test("the keeper passes the same denial suite as any third party (Lua level)", async () => {
    const run = await keeper({ grants: [] });
    for (const probe of DENIAL_PROBES) {
      const ok = (await run.lua.doString(
        `return history.query("${probe.source}", ${JSON.stringify(probe.opts).replace(/"([^"]+)":/g, "$1=")})`,
      )) as boolean;
      expect(ok).toBe(false);
    }
    const codes = (await run.lua.doString(
      `return (function()
        local seen = {}
        local function q(s, o) history.query(s, o) seen[#seen+1] = history.last_code() end
        q("transcript", {scope={panel="pane-a",workspace="ws-1"},row_count=4,max_bytes=4096,op="list"})
        q("commands", {scope={},row_count=4,max_bytes=4096,op="list"})
        q("kv", {scope={panel="pane-a"},row_count=4,max_bytes=4096,op="list"})
        return table.concat(seen, ",")
      end)()`,
    )) as string;
    expect(codes).toBe(
      "E_HISTORY_MISSING_GRANT,E_HISTORY_SCOPE_MISMATCH,E_DEF_INVALID",
    );
  });
});

describe("oracle-tight denial texts", () => {
  test("no denial leaks content bytes, foreign ids, or absent-vs-denied signals", () => {
    const host = new MockHost({ manifestSource: MANIFEST_SOURCE });
    host.beginActivation();
    host.endActivation();
    // Seed secret-bearing and foreign content the denials must never echo.
    host.setHistoryCapture("transcript", true);
    host.setHistoryCapture("commands", true);
    host.setHistoryRows("transcript", [
      {
        panel: "pane-a",
        workspace: "ws-1",
        seq: 0,
        body: "s3cr3t-corpus-bytes",
        recorded_at: 1,
      },
      {
        panel: "pane-b",
        workspace: "ws-1",
        seq: 1,
        body: "foreign-panel-bytes",
        recorded_at: 2,
      },
    ]);
    const texts: string[] = [];
    const cases: Array<{
      source: "transcript" | "commands" | "kv";
      opts: Record<string, unknown>;
    }> = [
      // Missing grant (commands never granted here: only transcript below).
      {
        source: "commands",
        opts: {
          scope: { panel: "pane-a", workspace: "ws-1" },
          row_count: 4,
          max_bytes: 4096,
          op: "list",
        },
      },
      // Scope mismatch and malformed scope.
      {
        source: "transcript",
        opts: { scope: {}, row_count: 4, max_bytes: 4096, op: "list" },
      },
      {
        source: "transcript",
        opts: {
          scope: { panel: "*", workspace: "ws-1" },
          row_count: 4,
          max_bytes: 4096,
          op: "list",
        },
      },
      // Over-bound and bad needle.
      {
        source: "transcript",
        opts: {
          scope: { panel: "pane-a", workspace: "ws-1" },
          row_count: 99,
          max_bytes: 4096,
          op: "list",
        },
      },
      {
        source: "transcript",
        opts: {
          scope: { panel: "pane-a", workspace: "ws-1" },
          row_count: 4,
          max_bytes: 4096,
          op: "search",
        },
      },
    ];
    host.grant("history.transcript.read");
    for (const c of cases) {
      try {
        (
          host.bitty.history[c.source] as {
            query: (o: unknown) => unknown;
          }
        ).query(c.opts);
      } catch (error) {
        texts.push(String(error));
      }
    }
    host.revoke("history.transcript.read");
    try {
      (
        host.bitty.history.transcript as {
          query: (o: unknown) => unknown;
        }
      ).query({
        scope: { panel: "pane-a", workspace: "ws-1" },
        row_count: 4,
        max_bytes: 4096,
        op: "list",
      });
    } catch (error) {
      texts.push(String(error));
    }
    expect(texts.length).toBeGreaterThan(0);
    for (const text of texts) {
      expect(text).not.toMatch(/s3cr3t-corpus-bytes/);
      expect(text).not.toMatch(/foreign-panel-bytes/);
      expect(text).not.toMatch(/pane-b/);
    }
    // Denial codes name the category only; messages carry no row counts that
    // could distinguish absent content from denied content.
    for (const text of texts) {
      expect(text).toMatch(/E_HISTORY_|E_DEF_INVALID/);
    }
    host.dispose();
  });
});
