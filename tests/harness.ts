/**
 * Runs `lua/history/init.lua` in a real Lua VM (wasmoon) against the SDK
 * mock host (bitty-plugin-sdk `MockHost`).
 *
 * The mock host owns every contract check: manifest linting, capability
 * gates, the activation registration window, scoped grants, opt-in capture,
 * row/byte caps and per-plugin window budgets, purge/expiry, trust
 * admission, safe-mode denial, and the W-01 focusable-overlay lifecycle
 * (single owner, scene validation, scene budgets). The harness bridges the
 * injected `bitty` table into Lua, dispatches the three one-shot query
 * commands, records the overlay calls the plugin makes (acquire, update
 * scene, release), and exposes scalar state queries so tests assert on plain
 * values.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { MockHost } from "bitty-plugin-sdk";
import { LuaFactory, type LuaEngine } from "wasmoon";

const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
export const MANIFEST_SOURCE = readFileSync(
  join(REPO_ROOT, "bitty-plugin.toml"),
  "utf8",
);
export const ENTRY_SOURCE = readFileSync(
  join(REPO_ROOT, "lua/history/init.lua"),
  "utf8",
);

/** Read capabilities the manifest requests; tests grant them by default. */
export const HISTORY_CAPABILITIES = [
  "history.transcript.read",
  "history.commands.read",
  "history.kv.read",
] as const;

/** The single presentation grant a queried page is painted with. */
export const PRESENTATION_CAPABILITIES = ["ui.overlay.focus"] as const;

/** Every capability the manifest declares. */
export const MANIFEST_CAPABILITIES = [
  ...HISTORY_CAPABILITIES,
  ...PRESENTATION_CAPABILITIES,
] as const;

export const TRANSCRIPT_COMMAND = "bitty-terminal.history:query-transcript";
export const COMMANDS_COMMAND = "bitty-terminal.history:query-commands";
export const KV_COMMAND = "bitty-terminal.history:query-kv";

/** One scene the plugin handed to `bitty.ui.overlay.update`. */
export interface OverlayUpdate {
  /** Scene as the host received it (Lua table marshalled to JS). */
  readonly scene: Record<string, unknown>;
  /** Whether the mock host accepted the scene. */
  readonly accepted: boolean;
}

/** Overlay calls observed during the run. */
export interface OverlayLog {
  /** `acquire` attempts, including the ones the host denied. */
  readonly acquireCalls: number;
  /** Successful `acquire` calls. */
  readonly acquires: number;
  /** `release` calls in order, with the reason argument. */
  readonly releases: string[];
  /** Every `update` call in order. */
  readonly updates: OverlayUpdate[];
}

export interface HistoryRun {
  readonly host: MockHost;
  readonly lua: LuaEngine;
  /** Overlay call log (mutable view owned by the harness). */
  readonly overlay: OverlayLog;
  /** Scalar Lua state query: `history.last_code()`, `history.record_count()`. */
  query(expr: string): Promise<unknown>;
  close(): void;
}

export interface HistoryRunOptions {
  readonly grants?: readonly string[];
  readonly safeMode?: boolean;
  readonly trustLevel?: string;
  readonly pluginApiVersion?: string;
  /**
   * Replace one source's `bitty.history.<source>.query` result. Used to model
   * a host that delivers a malformed record; the real mock host only ever
   * builds well-formed pages.
   */
  readonly pageOverrides?: Partial<
    Record<"transcript" | "commands" | "kv", unknown>
  >;
}

const factory = new LuaFactory();

/**
 * Map JS `null` results to `undefined` so they reach Lua as `nil` (the
 * mock host models Lua `nil` as `null`; wasmoon cannot push `null`).
 */
function nilSafe<T>(table: T): T {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(table as Record<string, unknown>)) {
    if (typeof value === "function") {
      out[key] = (...args: unknown[]): unknown => {
        const result = (value as (...a: unknown[]) => unknown)(...args);
        return result === null ? undefined : result;
      };
    } else if (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value)
    ) {
      out[key] = nilSafe(value);
    } else {
      out[key] = value;
    }
  }
  return out as T;
}

interface MutableOverlayLog {
  acquireCalls: number;
  acquires: number;
  releases: string[];
  updates: OverlayUpdate[];
}

interface OverlayBridge {
  acquire(spec?: unknown): number;
  update(handle: number, scene: Record<string, unknown>): boolean;
  poll(handle: number): unknown;
  release(handle: number, reason?: string | null): boolean;
}

/**
 * Wrap the injected overlay bridge so tests can see the scene the plugin
 * painted. The wrappers delegate to the mock host, so every capability,
 * ownership, and scene-budget check still runs; a rejected call is recorded
 * as `accepted: false` and re-thrown for the plugin's own guard.
 */
function instrumentOverlay(
  overlay: OverlayBridge,
  log: MutableOverlayLog,
): void {
  const acquire = overlay.acquire.bind(overlay);
  const update = overlay.update.bind(overlay);
  const release = overlay.release.bind(overlay);
  overlay.acquire = (spec?: unknown): number => {
    log.acquireCalls += 1;
    const handle = acquire(spec);
    log.acquires += 1;
    return handle;
  };
  overlay.update = (
    handle: number,
    scene: Record<string, unknown>,
  ): boolean => {
    try {
      const accepted = update(handle, scene);
      log.updates.push({ scene, accepted });
      return accepted;
    } catch (error) {
      log.updates.push({ scene, accepted: false });
      throw error;
    }
  };
  overlay.release = (handle: number, reason?: string | null): boolean => {
    log.releases.push(reason ?? "");
    return release(handle, reason);
  };
}

/** Activate the plugin once: grants, init.lua, end activation. */
export async function activateHistory(
  options: HistoryRunOptions = {},
): Promise<HistoryRun> {
  const host = new MockHost({
    manifestSource: MANIFEST_SOURCE,
    ...(options.safeMode !== undefined ? { safeMode: options.safeMode } : {}),
    ...(options.trustLevel !== undefined
      ? { trustLevel: options.trustLevel }
      : {}),
    ...(options.pluginApiVersion !== undefined
      ? { pluginApiVersion: options.pluginApiVersion }
      : {}),
  });
  for (const capability of options.grants ?? MANIFEST_CAPABILITIES) {
    host.grant(capability);
  }
  host.beginActivation();

  const overlay: MutableOverlayLog = {
    acquireCalls: 0,
    acquires: 0,
    releases: [],
    updates: [],
  };
  const bitty = nilSafe(host.bitty) as unknown as {
    ui: { overlay: OverlayBridge };
    history: Record<string, { query: (opts?: unknown) => unknown }>;
  };
  instrumentOverlay(bitty.ui.overlay, overlay);
  for (const [source, page] of Object.entries(options.pageOverrides ?? {})) {
    bitty.history[source]!.query = () => page;
  }

  const lua = await factory.createEngine({ injectObjects: false });
  lua.global.set("bitty", bitty);
  const run: HistoryRun = {
    host,
    lua,
    overlay,
    async query(expr: string): Promise<unknown> {
      return lua.doString(`return ${expr}`);
    },
    close(): void {
      lua.global.close();
    },
  };
  try {
    await lua.doString(ENTRY_SOURCE);
    host.endActivation();
  } catch (error) {
    lua.global.close();
    throw error;
  }
  return run;
}

/** Dispatch a session command by qualified name. */
export function dispatch(
  run: HistoryRun,
  command: string,
  args: unknown = {},
): unknown {
  return run.host.dispatchCommand(command, args);
}

/** Scalar state readers (plain values, no table conversion). */
export async function lastCode(run: HistoryRun): Promise<string> {
  return (await run.query("history.last_code()")) as string;
}

export async function recordCount(run: HistoryRun): Promise<number> {
  return (await run.query("history.record_count()")) as number;
}

export async function skippedCount(run: HistoryRun): Promise<number> {
  return (await run.query("history.skipped_count()")) as number;
}

export async function recordBody(
  run: HistoryRun,
  index: number,
): Promise<string | null> {
  return (await run.query(`history.record_body(${index})`)) as string | null;
}

export async function recordLabel(
  run: HistoryRun,
  index: number,
): Promise<string | null> {
  return (await run.query(`history.record_label(${index})`)) as string | null;
}

/** Text rows of the last accepted scene, in paint order. */
export function sceneRows(scene: Record<string, unknown>): string[] {
  const children = (scene.children ?? []) as Array<{
    kind?: string;
    text?: string;
  }>;
  return children
    .filter((child) => child.kind === "Text")
    .map((child) => String(child.text ?? ""));
}

/** Text rows of the last accepted overlay update, or an empty list. */
export function lastPaintedRows(run: HistoryRun): string[] {
  const accepted = run.overlay.updates.filter((entry) => entry.accepted);
  const last = accepted[accepted.length - 1];
  return last === undefined ? [] : sceneRows(last.scene);
}
