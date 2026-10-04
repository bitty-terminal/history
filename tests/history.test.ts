/**
 * History behavior against the SDK mock host: scoped bounded snapshot
 * queries over the three queryable sources (transcript, commands, own KV)
 * with typed denials, untrusted-label handling, and purge/expiry respect.
 *
 * The mock host owns every capability, grant, scope, capture, bound,
 * purge, trust, and safe-mode check; tests assert plugin policy (explicit
 * scope and bound on every read, per-source grants with no bundling, no
 * session-snapshot access, no streaming, VM-only delivery with labeled
 * redacted records) and that denial shapes stay oracle-tight.
 */

import { afterEach, describe, expect, test } from "bun:test";

import { lintManifestSource, MockHost } from "bitty-plugin-sdk";
import { LuaFactory } from "wasmoon";

import {
  activateHistory,
  COMMANDS_COMMAND,
  dispatch,
  ENTRY_SOURCE,
  HISTORY_CAPABILITIES,
  KV_COMMAND,
  lastCode,
  MANIFEST_SOURCE,
  recordBody,
  recordCount,
  recordLabel,
  TRANSCRIPT_COMMAND,
  type HistoryRun,
} from "./harness.js";

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

function scope(panel = "pane-a", workspace = "ws-1"): string {
  return `{panel="${panel}",workspace="${workspace}"}`;
}

async function luaQuery(
  run: HistoryRun,
  source: string,
  opts: string,
): Promise<boolean> {
  return (await run.lua.doString(
    `return history.query("${source}", ${opts})`,
  )) as boolean;
}

describe("manifest", () => {
  test("passes the authoritative SDK linter with zero errors", () => {
    const result = lintManifestSource(MANIFEST_SOURCE);
    expect(
      result.diagnostics.filter((entry) => entry.severity === "error"),
    ).toEqual([]);
  });

  test("high-risk consent warnings name exactly the three history grants", () => {
    const result = lintManifestSource(MANIFEST_SOURCE);
    expect(
      result.diagnostics.map((entry) => `${entry.code}:${entry.path}`).sort(),
    ).toEqual(
      [
        "capabilities.high-risk:history.commands.read",
        "capabilities.high-risk:history.kv.read",
        "capabilities.high-risk:history.transcript.read",
      ].sort(),
    );
  });

  test("declares exactly the public history-read set and no export grant", () => {
    expect([...HISTORY_CAPABILITIES].sort()).toEqual(
      [
        "history.commands.read",
        "history.kv.read",
        "history.transcript.read",
      ].sort(),
    );
    // Declared authority lives in TOML keys, not prose: the [capabilities]
    // section must grant exactly the triple (the `bitty-terminal.*` plugin
    // id prefix is not authority, so a bare `terminal.` substring probe
    // would false-positive on it). Nothing beyond the triple may be `= true`.
    const section = MANIFEST_SOURCE.split("[capabilities]")[1].split("[")[0];
    const granted = section
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.endsWith("= true"))
      .map((line) => line.split("=")[0].trim());
    expect(granted.sort()).toEqual([...HISTORY_CAPABILITIES].sort());
    const declared = MANIFEST_SOURCE.split("\n")
      .filter((line) => !line.trimStart().startsWith("#"))
      .join("\n");
    expect(declared).not.toMatch(/clipboard\.write\s*=\s*true/);
    expect(declared).not.toMatch(/process\.spawn/);
    expect(declared).not.toMatch(/bitty\.terminal\./);
    expect(declared).not.toMatch(/bitty\.selection\./);
    expect(declared).not.toMatch(/bitty\.store/);
  });
});

describe("pure policy without a host", () => {
  test("the entry point loads with bitty absent and checks compat", async () => {
    const factory = new LuaFactory();
    const lua = await factory.createEngine({ injectObjects: false });
    try {
      await lua.doString(ENTRY_SOURCE);
      expect(await lua.doString("return history.check_compat('1.0.0')")).toBe(
        true,
      );
      expect(await lua.doString("return history.check_compat('1.9.9')")).toBe(
        true,
      );
      expect(await lua.doString("return history.check_compat('2.0.0')")).toBe(
        false,
      );
      expect(await lua.doString("return history.check_compat('nope')")).toBe(
        false,
      );
      // Forbidden session sources fail closed before any host call.
      expect(
        await lua.doString(
          "return (function() local _, code = history.validate_query('session', {}) return code end)()",
        ),
      ).toBe("E_DEF_INVALID");
      expect(
        await lua.doString(
          "return (function() local _, code = history.validate_query('snapshot', {}) return code end)()",
        ),
      ).toBe("E_DEF_INVALID");
      // Unknown sources fail closed.
      expect(
        await lua.doString(
          "return (function() local _, code = history.validate_query('nope', {}) return code end)()",
        ),
      ).toBe("E_DEF_INVALID");
      // Wildcard and blank scopes are malformed.
      expect(
        await lua.doString(
          "return (function() local _, code = history.validate_scope('transcript', {panel='*'}) return code end)()",
        ),
      ).toBe("E_DEF_INVALID");
      expect(
        await lua.doString(
          "return (function() local _, code = history.validate_scope('transcript', {panel='all'}) return code end)()",
        ),
      ).toBe("E_DEF_INVALID");
      // Unscoped transcript queries are scope mismatch, not malformed.
      expect(
        await lua.doString(
          "return (function() local _, code = history.validate_scope('transcript', {}) return code end)()",
        ),
      ).toBe("E_HISTORY_SCOPE_MISMATCH");
      // KV forbids panel/workspace extents.
      expect(
        await lua.doString(
          "return (function() local _, code = history.validate_scope('kv', {panel='pane-a'}) return code end)()",
        ),
      ).toBe("E_DEF_INVALID");
    } finally {
      lua.global.close();
    }
  });
});

describe("scoped bounded snapshots with typed denials", () => {
  test("missing grant denies before capture is even consulted", async () => {
    const run = await history({ grants: [] });
    const ok = await luaQuery(
      run,
      "transcript",
      `{scope=${scope()},row_count=4,max_bytes=4096,op="list"}`,
    );
    expect(ok).toBe(false);
    expect(await lastCode(run)).toBe("E_HISTORY_MISSING_GRANT");
    expect(await recordCount(run)).toBe(0);
  });

  test("capture-disabled source denies with the grant held", async () => {
    const run = await history();
    const ok = await luaQuery(
      run,
      "transcript",
      `{scope=${scope()},row_count=4,max_bytes=4096,op="list"}`,
    );
    expect(ok).toBe(false);
    expect(await lastCode(run)).toBe("E_HISTORY_CAPTURE_DISABLED");
  });

  test("unscoped query denies as scope mismatch, wildcard as malformed", async () => {
    const run = await history();
    run.host.setHistoryCapture("transcript", true);
    let ok = await luaQuery(
      run,
      "transcript",
      `{scope={},row_count=4,max_bytes=4096,op="list"}`,
    );
    expect(ok).toBe(false);
    expect(await lastCode(run)).toBe("E_HISTORY_SCOPE_MISMATCH");
    ok = await luaQuery(
      run,
      "transcript",
      `{scope={panel="*",workspace="ws-1"},row_count=4,max_bytes=4096,op="list"}`,
    );
    expect(ok).toBe(false);
    expect(await lastCode(run)).toBe("E_DEF_INVALID");
  });

  test("transcript success returns redacted labeled attributed records", async () => {
    const run = await history();
    run.host.setHistoryCapture("transcript", true);
    run.host.setHistoryRows("transcript", [
      {
        panel: "pane-a",
        workspace: "ws-1",
        seq: 0,
        body: "redacted output line one",
        command: "make check",
        recorded_at: 10,
        actor: "user",
      },
      {
        panel: "pane-a",
        workspace: "ws-1",
        seq: 1,
        body: "redacted output line two",
        recorded_at: 11,
      },
      {
        panel: "pane-b",
        workspace: "ws-1",
        seq: 2,
        body: "foreign panel bytes never cross",
        recorded_at: 12,
      },
    ]);
    const ok = await luaQuery(
      run,
      "transcript",
      `{scope=${scope()},row_count=4,max_bytes=4096,op="list"}`,
    );
    expect(ok).toBe(true);
    expect(await lastCode(run)).toBe("ok");
    expect(await recordCount(run)).toBe(2);
    expect(await recordBody(run, 1)).toBe("redacted output line one");
    expect(await recordBody(run, 2)).toBe("redacted output line two");
    // Every record carries the Core-attached untrusted label.
    expect(await recordLabel(run, 1)).toBe("untrusted-observation");
    expect(await recordLabel(run, 2)).toBe("untrusted-observation");
    const page = (await run.query("history.last_page()")) as {
      freshness: string;
      total_in_scope: number;
      records: Array<{ redacted: boolean; label: string }>;
    };
    expect(page.freshness).toBe("point-in-time-no-guarantee");
    expect(page.total_in_scope).toBe(2);
    expect(page.records.every((r) => r.redacted === true)).toBe(true);
    expect(page.records.every((r) => r.label === "untrusted-observation")).toBe(
      true,
    );
  });

  test("source isolation: a transcript grant never implies commands or kv", async () => {
    const run = await history({ grants: ["history.transcript.read"] });
    run.host.setHistoryCapture("transcript", true);
    run.host.setHistoryCapture("commands", true);
    const okCommands = await luaQuery(
      run,
      "commands",
      `{scope=${scope()},row_count=4,max_bytes=4096,op="list"}`,
    );
    expect(okCommands).toBe(false);
    expect(await lastCode(run)).toBe("E_HISTORY_MISSING_GRANT");
    const okKv = await luaQuery(
      run,
      "kv",
      `{row_count=4,max_bytes=4096,op="list"}`,
    );
    expect(okKv).toBe(false);
    expect(await lastCode(run)).toBe("E_HISTORY_MISSING_GRANT");
  });

  test("commands tail and search read with explicit bounds", async () => {
    const run = await history();
    run.host.setHistoryCapture("commands", true);
    run.host.setHistoryRows("commands", [
      { panel: "pane-a", workspace: "ws-1", seq: 0, body: "make check" },
      { panel: "pane-a", workspace: "ws-1", seq: 1, body: "bun test" },
      { panel: "pane-a", workspace: "ws-1", seq: 2, body: "make lint" },
    ]);
    let ok = await luaQuery(
      run,
      "commands",
      `{scope=${scope()},row_count=2,max_bytes=4096,op="tail"}`,
    );
    expect(ok).toBe(true);
    expect(await recordCount(run)).toBe(2);
    expect(await recordBody(run, 1)).toBe("bun test");
    ok = await luaQuery(
      run,
      "commands",
      `{scope=${scope()},row_count=4,max_bytes=4096,op="search",needle="make"}`,
    );
    expect(ok).toBe(true);
    expect(await recordCount(run)).toBe(2);
    // Search without a needle denies as over-bound, never as an open scan.
    ok = await luaQuery(
      run,
      "commands",
      `{scope=${scope()},row_count=4,max_bytes=4096,op="search"}`,
    );
    expect(ok).toBe(false);
    expect(await lastCode(run)).toBe("E_HISTORY_OVER_BOUND");
  });

  test("own-KV reads stay in the caller namespace; foreign rows never surface", async () => {
    const run = await history();
    run.host.setHistoryRows("kv", [
      { owner: "bitty-terminal.history", seq: 0, body: "own state" },
      { owner: "example.foreign", seq: 1, body: "foreign state" },
    ]);
    const ok = await luaQuery(
      run,
      "kv",
      `{row_count=4,max_bytes=4096,op="list"}`,
    );
    expect(ok).toBe(true);
    expect(await recordCount(run)).toBe(1);
    expect(await recordBody(run, 1)).toBe("own state");
    // KV rejects panel/workspace extents: the caller namespace is the scope.
    const scoped = await luaQuery(
      run,
      "kv",
      `{scope=${scope()},row_count=4,max_bytes=4096,op="list"}`,
    );
    expect(scoped).toBe(false);
    expect(await lastCode(run)).toBe("E_DEF_INVALID");
  });

  test("over-bound requests deny, never clamp silently", async () => {
    const run = await history();
    run.host.setHistoryCapture("transcript", true);
    for (const opts of [
      `{scope=${scope()},row_count=17,max_bytes=4096,op="list"}`,
      `{scope=${scope()},row_count=4,max_bytes=5000,op="list"}`,
      `{scope=${scope()},row_count=0,max_bytes=4096,op="list"}`,
      `{scope=${scope()},row_count=4,max_bytes=0,op="list"}`,
    ]) {
      const ok = await luaQuery(run, "transcript", opts);
      expect(ok).toBe(false);
      expect(await lastCode(run)).toBe("E_HISTORY_OVER_BOUND");
    }
  });

  test("purged content surfaces as typed unavailability, never a silent gap", async () => {
    const run = await history();
    run.host.setHistoryCapture("transcript", true);
    run.host.setHistoryRows("transcript", [
      {
        panel: "pane-a",
        workspace: "ws-1",
        seq: 0,
        body: "expired bytes",
        purged: true,
      },
    ]);
    const ok = await luaQuery(
      run,
      "transcript",
      `{scope=${scope()},row_count=4,max_bytes=4096,op="list"}`,
    );
    expect(ok).toBe(false);
    expect(await lastCode(run)).toBe("E_HISTORY_UNAVAILABLE");
    expect(await recordCount(run)).toBe(0);
  });

  test("session snapshots are never queryable, even with grants held", async () => {
    const run = await history();
    for (const source of ["session", "snapshot", "session-snapshot"]) {
      const ok = await luaQuery(
        run,
        source,
        `{scope=${scope()},row_count=4,max_bytes=4096,op="list"}`,
      );
      expect(ok).toBe(false);
      expect(await lastCode(run)).toBe("E_DEF_INVALID");
    }
  });

  test("safe mode and untrusted levels deny identically for every grant", async () => {
    const safe = await history({ safeMode: true });
    const okSafe = await luaQuery(
      safe,
      "transcript",
      `{scope=${scope()},row_count=4,max_bytes=4096,op="list"}`,
    );
    expect(okSafe).toBe(false);
    expect(await lastCode(safe)).toBe("E_HISTORY_SAFE_MODE");
    for (const trustLevel of ["L0", "L3", "L4", "unknown"]) {
      const run = await history({ trustLevel });
      const ok = await luaQuery(
        run,
        "transcript",
        `{scope=${scope()},row_count=4,max_bytes=4096,op="list"}`,
      );
      expect(ok).toBe(false);
      expect(await lastCode(run)).toBe("E_HISTORY_TRUST_DENIED");
    }
  });

  test("revoked grants stay distinct from missing grants without leaking which", async () => {
    const run = await history();
    run.host.setHistoryCapture("transcript", true);
    run.host.revoke("history.transcript.read");
    const ok = await luaQuery(
      run,
      "transcript",
      `{scope=${scope()},row_count=4,max_bytes=4096,op="list"}`,
    );
    expect(ok).toBe(false);
    expect(await lastCode(run)).toBe("E_HISTORY_REVOKED_GRANT");
  });
});

describe("commands are one-shot snapshots, never streams", () => {
  test("the three query commands dispatch and return typed ok/code", async () => {
    const run = await history();
    run.host.setHistoryCapture("transcript", true);
    run.host.setHistoryCapture("commands", true);
    run.host.setHistoryRows("transcript", [
      { panel: "pane-a", workspace: "ws-1", seq: 0, body: "t0" },
    ]);
    run.host.setHistoryRows("commands", [
      { panel: "pane-a", workspace: "ws-1", seq: 0, body: "c0" },
    ]);
    run.host.setHistoryRows("kv", [
      { owner: "bitty-terminal.history", seq: 0, body: "k0" },
    ]);
    const t = dispatch(run, TRANSCRIPT_COMMAND, {
      scope: { panel: "pane-a", workspace: "ws-1" },
      row_count: 4,
      max_bytes: 4096,
      op: "list",
    }) as { ok: boolean; code: string };
    expect(t.ok).toBe(true);
    expect(t.code).toBe("ok");
    const c = dispatch(run, COMMANDS_COMMAND, {
      scope: { panel: "pane-a", workspace: "ws-1" },
      row_count: 4,
      max_bytes: 4096,
      op: "list",
    }) as { ok: boolean; code: string };
    expect(c.ok).toBe(true);
    const k = dispatch(run, KV_COMMAND, {
      row_count: 4,
      max_bytes: 4096,
      op: "list",
    }) as { ok: boolean; code: string };
    expect(k.ok).toBe(true);
    // A fresh query replaces the page; no cursor is held across calls.
    expect(await recordBody(run, 1)).toBe("k0");
  });

  test("the plugin subscribes to no events and touches only bitty.history", async () => {
    const section = MANIFEST_SOURCE.split("[lazy]")[1] ?? "";
    expect(section).not.toMatch(/events/);
    const { readFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { fileURLToPath } = await import("node:url");
    const root = fileURLToPath(new URL("..", import.meta.url));
    const source = readFileSync(join(root, "lua/history/init.lua"), "utf8");
    const code = source
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("--"))
      .join("\n");
    const namespaces = new Set(
      [...code.matchAll(/bitty\.([A-Za-z_]+)/g)].map((m) => m[1]),
    );
    for (const ns of namespaces) {
      expect(["api_version", "commands", "history"]).toContain(ns);
    }
    expect(code).not.toMatch(/bitty\.terminal/);
    expect(code).not.toMatch(/bitty\.selection/);
    expect(code).not.toMatch(/bitty\.store/);
    expect(code).not.toMatch(/bitty\.process/);
    expect(code).not.toMatch(/bitty\.events/);
    expect(code).not.toMatch(/\brequire\s*\(/);
    expect(code).not.toMatch(/dofile|loadfile|loadstring/);
  });

  test("mismatch disables with a diagnostic and registers nothing", async () => {
    const factory = new LuaFactory();
    const lua = await factory.createEngine({ injectObjects: false });
    try {
      const seen: string[] = [];
      lua.global.set("bitty", {
        api_version: "99.0.0",
        commands: {
          register: () => {
            seen.push("register");
            return 1;
          },
        },
      });
      await lua.doString(ENTRY_SOURCE);
      expect(seen).toEqual([]);
      expect(await lua.doString("return history.disabled")).toBe(true);
      expect(await lua.doString("return history.disabled_reason")).toMatch(
        /\^1\.0/,
      );
    } finally {
      lua.global.close();
    }
  });

  test("host-level API mismatch fails activation with no partial state", () => {
    const host = new MockHost({
      manifestSource: MANIFEST_SOURCE,
      pluginApiVersion: "99.0.0",
    });
    expect(() => host.beginActivation()).toThrow(/E_LIFECYCLE_STATE/);
    expect(() => host.dispatchCommand(TRANSCRIPT_COMMAND, {})).toThrow(
      /E_GENERATION_DISPOSED/,
    );
  });
});
