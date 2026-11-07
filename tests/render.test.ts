/**
 * Presentation behavior for the History plugin (bitty#2967).
 *
 * A successful query must paint its page into the focusable overlay: the
 * command acquires the W-01 surface, updates it with a `List` of `Text` rows,
 * and keeps the session while the user reads. These specs model exactly the
 * host surfaces the plugin calls (`bitty.ui.overlay.acquire`/`update`/
 * `release` under `ui.overlay.focus`) and assert the scene the host receives,
 * so a regression that returns `{ok, code}` without mounting a surface fails
 * here instead of in a headed session.
 */

import { afterEach, describe, expect, test } from "bun:test";

import { LuaFactory } from "wasmoon";

import {
  activateHistory,
  COMMANDS_COMMAND,
  dispatch,
  ENTRY_SOURCE,
  HISTORY_CAPABILITIES,
  KV_COMMAND,
  lastPaintedRows,
  recordCount,
  skippedCount,
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

const PANEL_SCOPE = { panel: "pane-a", workspace: "ws-1" };

function seed(
  run: HistoryRun,
  bodies: readonly string[],
  source = "transcript",
): void {
  run.host.setHistoryCapture(source, true);
  run.host.setHistoryRows(
    source,
    bodies.map((body, seq) => ({
      panel: "pane-a",
      workspace: "ws-1",
      seq,
      body,
    })),
  );
}

function transcriptArgs(
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    scope: PANEL_SCOPE,
    row_count: 4,
    max_bytes: 4096,
    op: "list",
    ...extra,
  };
}

describe("query paints its page into the focusable overlay", () => {
  test("a two-record page paints both rows in host order", async () => {
    const run = await history();
    seed(run, ["redacted output line one", "redacted output line two"]);

    const result = dispatch(run, TRANSCRIPT_COMMAND, transcriptArgs()) as {
      ok: boolean;
      code: string;
    };

    expect(result.ok).toBe(true);
    expect(result.code).toBe("ok");
    expect(run.overlay.acquires).toBe(1);
    expect(run.overlay.updates).toHaveLength(1);
    expect(run.overlay.updates[0]?.accepted).toBe(true);
    expect(run.overlay.updates[0]?.scene.kind).toBe("List");
    expect(lastPaintedRows(run)).toEqual([
      "History: transcript",
      "redacted output line one",
      "redacted output line two",
    ]);
  });

  test("an empty page paints the typed no-records row instead of a blank overlay", async () => {
    const run = await history();
    run.host.setHistoryCapture("transcript", true);
    run.host.setHistoryRows("transcript", [
      {
        panel: "pane-b",
        workspace: "ws-1",
        seq: 0,
        body: "out of scope",
      },
    ]);

    const result = dispatch(run, TRANSCRIPT_COMMAND, transcriptArgs()) as {
      ok: boolean;
      code: string;
    };

    expect(result.ok).toBe(true);
    expect(await recordCount(run)).toBe(0);
    expect(lastPaintedRows(run)).toEqual([
      "History: transcript",
      "No records in scope",
    ]);
  });

  test("a malformed record is skipped with a typed note and the rest still paint", async () => {
    const attribution = {
      panel: "pane-a",
      workspace: "ws-1",
      recorded_at: 1,
    };
    const run = await history({
      pageOverrides: {
        transcript: {
          freshness: "point-in-time-no-guarantee",
          total_in_scope: 2,
          records: [
            {
              seq: 0,
              body: "admitted row",
              truncated: false,
              redacted: true,
              label: "untrusted-observation",
              attribution,
            },
            {
              // Missing the Core-attached untrusted label: never delivered.
              seq: 1,
              body: "unlabeled row",
              truncated: false,
              redacted: true,
              label: "trusted",
              attribution,
            },
          ],
        },
      },
    });

    const result = dispatch(run, TRANSCRIPT_COMMAND, transcriptArgs()) as {
      ok: boolean;
      code: string;
    };

    expect(result.ok).toBe(true);
    expect(await recordCount(run)).toBe(1);
    expect(await skippedCount(run)).toBe(1);
    expect(lastPaintedRows(run)).toEqual([
      "History: transcript",
      "admitted row",
      "records skipped: 1 (invalid-record)",
    ]);
  });

  test("a second query repaints the held session instead of acquiring again", async () => {
    const run = await history();
    seed(run, ["first page"]);
    dispatch(run, TRANSCRIPT_COMMAND, transcriptArgs());
    seed(run, ["second page"]);
    dispatch(run, TRANSCRIPT_COMMAND, transcriptArgs());

    expect(run.overlay.acquires).toBe(1);
    expect(run.overlay.updates).toHaveLength(2);
    expect(lastPaintedRows(run)).toEqual([
      "History: transcript",
      "second page",
    ]);
  });

  test("a session Core revoked (focus switch) is re-acquired on the next paint", async () => {
    const run = await history();
    seed(run, ["before switch"]);
    dispatch(run, TRANSCRIPT_COMMAND, transcriptArgs());
    run.host.simulateOverlayFocusSwitch();
    seed(run, ["after switch"]);
    dispatch(run, TRANSCRIPT_COMMAND, transcriptArgs());

    expect(run.overlay.acquires).toBe(2);
    // One accepted paint, one rejected update on the stale handle, one
    // accepted paint on the fresh surface.
    expect(run.overlay.updates.map((entry) => entry.accepted)).toEqual([
      true,
      false,
      true,
    ]);
    expect(lastPaintedRows(run)).toEqual([
      "History: transcript",
      "after switch",
    ]);
  });

  test("a denied query releases the held overlay so stale rows do not outlive it", async () => {
    const run = await history();
    seed(run, ["stale row"]);
    dispatch(run, TRANSCRIPT_COMMAND, transcriptArgs());
    run.host.revoke("history.transcript.read");

    const denied = dispatch(run, TRANSCRIPT_COMMAND, transcriptArgs()) as {
      ok: boolean;
      code: string;
    };

    expect(denied.ok).toBe(false);
    expect(denied.code).toBe("E_HISTORY_REVOKED_GRANT");
    expect(run.overlay.releases).toEqual(["cancelled"]);
  });

  test("without the presentation grant the query still answers and paints nothing", async () => {
    const run = await history({ grants: [...HISTORY_CAPABILITIES] });
    seed(run, ["data only"]);

    const result = dispatch(run, TRANSCRIPT_COMMAND, transcriptArgs()) as {
      ok: boolean;
      code: string;
    };

    expect(result.ok).toBe(true);
    expect(result.code).toBe("ok");
    expect(run.overlay.acquires).toBe(0);
    expect(run.overlay.updates).toEqual([]);
  });

  test("the commands and kv commands paint their own source title", async () => {
    const run = await history();
    seed(run, ["make check"], "commands");
    dispatch(run, COMMANDS_COMMAND, transcriptArgs());
    expect(lastPaintedRows(run)).toEqual(["History: commands", "make check"]);

    run.host.setHistoryRows("kv", [
      { owner: "bitty-terminal.history", seq: 0, body: "own state" },
    ]);
    dispatch(run, KV_COMMAND, {
      row_count: 4,
      max_bytes: 4096,
      op: "list",
    });
    expect(lastPaintedRows(run)).toEqual(["History: kv", "own state"]);
  });

  test("a maximum-size quote-heavy page stays inside the per-update scene ceiling", async () => {
    const run = await history();
    // 16 rows at the per-row 256-byte cap with JSON-escaping-heavy content:
    // raw page bytes stay inside max_bytes, while the escaped scene would
    // exceed the 4096-byte per-update call ceiling without a text budget.
    seed(
      run,
      Array.from({ length: 16 }, () => '"'.repeat(256)),
    );

    const result = dispatch(
      run,
      TRANSCRIPT_COMMAND,
      transcriptArgs({ row_count: 16, max_bytes: 4096 }),
    ) as { ok: boolean; code: string };

    expect(result.ok).toBe(true);
    expect(run.overlay.updates).toHaveLength(1);
    expect(run.overlay.updates[0]?.accepted).toBe(true);
    const rows = lastPaintedRows(run);
    // Title + shown rows + one typed budget note, never more than the host
    // accepts in one update.
    expect(rows.length).toBeLessThanOrEqual(19);
    expect(rows[0]).toBe("History: transcript");
    expect(rows[rows.length - 1]).toMatch(
      /^rows not shown: \d+ \(overlay-budget\)$/,
    );
    expect(
      rows.filter((row) => row === '"'.repeat(256)).length,
    ).toBeGreaterThan(0);
  });
});

describe("scene composition without a host", () => {
  async function loadPure(): Promise<{
    scene: (
      source: string,
      records: string,
      skipped: number,
    ) => Promise<{
      kind: string;
      children: Array<{ kind: string; text: string }>;
    }>;
    escaped: (text: string) => Promise<number>;
    close(): void;
  }> {
    const factory = new LuaFactory();
    const lua = await factory.createEngine({ injectObjects: false });
    await lua.doString(ENTRY_SOURCE);
    return {
      scene: async (source, records, skipped) =>
        (await lua.doString(
          `return history.build_scene(${JSON.stringify(source)}, ${records}, ${skipped})`,
        )) as {
          kind: string;
          children: Array<{ kind: string; text: string }>;
        },
      escaped: async (text) =>
        (await lua.doString(
          `return history.escaped_bytes(${JSON.stringify(text)})`,
        )) as number,
      close: () => lua.global.close(),
    };
  }

  test("rows are a List of Text in host order", async () => {
    const pure = await loadPure();
    try {
      const scene = await pure.scene(
        "transcript",
        '{ { body = "one" }, { body = "two" } }',
        0,
      );
      expect(scene.kind).toBe("List");
      expect(scene.children.map((child) => child.text)).toEqual([
        "History: transcript",
        "one",
        "two",
      ]);
    } finally {
      pure.close();
    }
  });

  test("empty and all-skipped answers still paint an explicit note", async () => {
    const pure = await loadPure();
    try {
      const empty = await pure.scene("kv", "{}", 0);
      expect(empty.children.map((child) => child.text)).toEqual([
        "History: kv",
        "No records in scope",
      ]);
      const skipped = await pure.scene("kv", "{}", 3);
      expect(skipped.children.map((child) => child.text)).toEqual([
        "History: kv",
        "records skipped: 3 (invalid-record)",
      ]);
    } finally {
      pure.close();
    }
  });

  test("the text budget counts JSON-escaped bytes, not raw bytes", async () => {
    const pure = await loadPure();
    try {
      expect(await pure.escaped("abc")).toBe(3);
      expect(await pure.escaped('"')).toBe(2);
      expect(await pure.escaped("\\")).toBe(2);
      expect(await pure.escaped("\n")).toBe(6);
    } finally {
      pure.close();
    }
  });
});
