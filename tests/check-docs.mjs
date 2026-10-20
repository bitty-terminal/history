#!/usr/bin/env bun
// User-docs gate: the README configuration table must describe exactly the
// keys declared under [settings] in bitty-plugin.toml, with the declared type
// and default. Missing keys, extra keys, and value drift fail closed.
//
// The check also pins the user-facing section order: Overview, Install,
// Commands, Configuration, Keybindings, Troubleshooting must be the first six
// H2 sections, before developer/architecture material.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST = join(ROOT, "bitty-plugin.toml");
const README = join(ROOT, "README.md");

const REQUIRED_SECTIONS = [
  "Overview",
  "Install",
  "Commands",
  "Configuration",
  "Keybindings",
  "Troubleshooting",
];

const problems = [];

function fail(message) {
  problems.push(message);
}

function read(path) {
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    console.error(`docs-check: cannot read ${path}: ${error.message}`);
    process.exit(1);
  }
}

// Split Markdown into H2 sections while ignoring headings inside fenced code.
function h2Sections(text) {
  const lines = text.split("\n");
  const sections = [];
  let current = null;
  let fence = null;
  for (const line of lines) {
    const fenceMatch = line.match(/^\s*(```+|~~~+)/);
    if (fenceMatch) {
      if (fence === null) {
        fence = fenceMatch[1][0];
      } else if (fenceMatch[1][0] === fence) {
        fence = null;
      }
    }
    if (fence === null) {
      const heading = line.match(/^##\s+(.+?)\s*$/);
      if (heading) {
        current = { title: heading[1], lines: [] };
        sections.push(current);
        continue;
      }
    }
    if (current) {
      current.lines.push(line);
    }
  }
  return sections;
}

// Parse the single-line `[settings]` declarations used by plugin manifests.
function declaredSettings(text) {
  const declared = new Map();
  let inSettings = false;
  for (const [index, raw] of text.split("\n").entries()) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) {
      continue;
    }
    const table = line.match(/^\[([^\]]+)\]$/);
    if (table) {
      inSettings = table[1] === "settings";
      continue;
    }
    if (!inSettings) {
      continue;
    }
    const match = line.match(
      /^([a-z][a-z0-9_]*)\s*=\s*\{\s*type\s*=\s*"([a-z-]+)"\s*,\s*default\s*=\s*(.+?)\s*\}$/,
    );
    if (!match) {
      fail(
        `bitty-plugin.toml:${index + 1}: [settings] entry is not the expected "key = { type = ..., default = ... }" shape: ${line}`,
      );
      continue;
    }
    const [, key, type, defaultLiteral] = match;
    if (declared.has(key)) {
      fail(`bitty-plugin.toml:${index + 1}: duplicate [settings] key "${key}"`);
      continue;
    }
    declared.set(key, { type, defaultLiteral });
  }
  return declared;
}

function cleanCell(cell) {
  return cell.replace(/^`|`$/g, "").trim();
}

// Extract documented settings rows. A settings row's first cell is exactly a
// single backticked key; requirement tables (for example `git` on PATH) do not
// match because they carry text outside the code span.
function documentedSettings(sectionLines) {
  const documented = new Map();
  for (const [index, line] of sectionLines.entries()) {
    const match = line.match(/^\|\s*`([a-z][a-z0-9_]*)`\s*\|(.*)\|\s*$/);
    if (!match) {
      continue;
    }
    const [, key, rest] = match;
    const cells = rest.split("|").map((cell) => cell.trim());
    if (cells.length !== 4) {
      fail(
        `README.md Configuration row for "${key}" must have 5 columns (Key, Type, Default, Description, Reload), got ${cells.length + 1}`,
      );
      continue;
    }
    if (documented.has(key)) {
      fail(`README.md Configuration table repeats key "${key}"`);
      continue;
    }
    documented.set(key, {
      line: index,
      type: cleanCell(cells[0]),
      defaultLiteral: cleanCell(cells[1]),
      description: cells[2],
      reload: cells[3],
    });
  }
  return documented;
}

const manifestText = read(MANIFEST);
const readmeText = read(README);
const sections = h2Sections(readmeText);
const titles = sections.map((section) => section.title);

const firstSix = titles.slice(0, REQUIRED_SECTIONS.length);
if (firstSix.join("\u0000") !== REQUIRED_SECTIONS.join("\u0000")) {
  fail(
    `README.md must start with these H2 sections in order: ${REQUIRED_SECTIONS.join(", ")}; found: ${firstSix.join(", ") || "(none)"}`,
  );
}

const configuration = sections.find(
  (section) => section.title === "Configuration",
);
if (!configuration) {
  fail("README.md is missing the ## Configuration section");
}

const declared = declaredSettings(manifestText);
const documented = configuration
  ? documentedSettings(configuration.lines)
  : new Map();

for (const [key, entry] of declared) {
  const row = documented.get(key);
  if (!row) {
    fail(`README.md Configuration is missing declared key "${key}"`);
    continue;
  }
  if (row.type !== entry.type) {
    fail(
      `README.md Configuration type for "${key}" is "${row.type}", manifest declares "${entry.type}"`,
    );
  }
  if (row.defaultLiteral !== entry.defaultLiteral) {
    fail(
      `README.md Configuration default for "${key}" is "${row.defaultLiteral}", manifest declares "${entry.defaultLiteral}"`,
    );
  }
  if (row.description === "") {
    fail(`README.md Configuration description for "${key}" is empty`);
  }
  if (row.reload === "") {
    fail(`README.md Configuration reload column for "${key}" is empty`);
  }
}

for (const key of documented.keys()) {
  if (!declared.has(key)) {
    fail(
      `README.md Configuration documents "${key}", which is not declared in bitty-plugin.toml [settings]`,
    );
  }
}

if (declared.size === 0) {
  if (!/No declared settings/.test(configuration?.lines.join("\n") ?? "")) {
    fail(
      'README.md ## Configuration must state "No declared settings." when the manifest declares none',
    );
  }
  if (documented.size > 0) {
    fail(
      "README.md ## Configuration lists settings rows but the manifest declares none",
    );
  }
}

if (problems.length > 0) {
  console.error("docs-check: user documentation does not match the manifest");
  for (const problem of problems) {
    console.error(`  - ${problem}`);
  }
  process.exit(1);
}

const summary =
  declared.size === 0
    ? "no [settings] keys"
    : `${declared.size} [settings] key(s): ${[...declared.keys()].join(", ")}`;
console.log(`docs-check: README configuration matches manifest (${summary})`);
