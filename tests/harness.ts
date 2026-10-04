/**
 * Runs `lua/history/init.lua` in a real Lua VM (wasmoon) against the SDK
 * mock host (bitty-plugin-sdk `MockHost`).
 *
 * The mock host owns every contract check: manifest linting, capability
 * gates, the activation registration window, scoped grants, opt-in capture,
 * row/byte caps and per-plugin window budgets, purge/expiry, trust
 * admission, and safe-mode denial. The harness only bridges the injected
 * `bitty` table into Lua, dispatches the three one-shot query commands,
 * and exposes scalar state queries so tests assert on plain values.
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

/** Capabilities the manifest requests; tests grant all of them by default. */
export const HISTORY_CAPABILITIES = [
  "history.transcript.read",
  "history.commands.read",
  "history.kv.read",
] as const;

export const TRANSCRIPT_COMMAND = "bitty-terminal.history:query-transcript";
export const COMMANDS_COMMAND = "bitty-terminal.history:query-commands";
export const KV_COMMAND = "bitty-terminal.history:query-kv";

export interface HistoryRun {
  readonly host: MockHost;
  readonly lua: LuaEngine;
  /** Scalar Lua state query: `history.last_code()`, `history.record_count()`. */
  query(expr: string): Promise<unknown>;
  close(): void;
}

export interface HistoryRunOptions {
  readonly grants?: readonly string[];
  readonly safeMode?: boolean;
  readonly trustLevel?: string;
  readonly pluginApiVersion?: string;
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
  for (const capability of options.grants ?? HISTORY_CAPABILITIES) {
    host.grant(capability);
  }
  host.beginActivation();

  const lua = await factory.createEngine({ injectObjects: false });
  lua.global.set("bitty", nilSafe(host.bitty));
  const run: HistoryRun = {
    host,
    lua,
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
