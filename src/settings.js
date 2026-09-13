import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { resolveAutoUpdateSettings, settingsPath } from "./scanner.js";

// Persisted user preferences, deliberately separate from state.json: the
// installer rewrites that file on every update, so a preference stored there
// would be wiped by the very auto-update it is meant to govern (issue #29).

export async function readSettingsFile(home) {
  try {
    return await readFile(settingsPath(home), "utf8");
  } catch {
    return null;
  }
}

// Merges the requested change into whatever is already on disk, so a future
// setting added alongside autoUpdate is not clobbered by this command.
export function mergeAutoUpdateSettings(fileContent, change) {
  let existing = {};
  try {
    const parsed = fileContent ? JSON.parse(fileContent) : null;
    if (parsed && typeof parsed === "object") existing = parsed;
  } catch {
    existing = {};
  }

  return {
    ...existing,
    autoUpdate: { ...(existing.autoUpdate ?? {}), ...change }
  };
}

export async function writeAutoUpdateSettings(change, home) {
  const path = settingsPath(home);
  const next = mergeAutoUpdateSettings(await readSettingsFile(home), change);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
  return next;
}

// Patch is reported as a fixed line rather than a toggle: it is not
// user-disableable, and saying so plainly is better than omitting it and
// leaving people to assume --no-autoupdate covered everything.
export function formatAutoUpdateSettings(resolved, path) {
  const state = (on) => (on ? "on" : "off");
  const lines = [
    "GForge settings",
    "",
    `  auto-update (patch)  on         always - security and critical fixes ship here`,
    `  auto-update (minor)  ${state(resolved.minor).padEnd(10)} 7-day quarantine before install`,
    `  auto-update (major)  ${state(resolved.major).padEnd(10)} 30-day quarantine, and only when tagged LTS`,
    "",
    `  source: ${resolved.source}${resolved.source === "settings" ? ` (${path})` : ""}`
  ];

  if (resolved.source === "env") {
    lines.push(
      "",
      "  Note: GFORGE_AUTO_UPDATE is set in the environment and overrides the",
      "  stored setting. Unset it for `gforge settings` to take effect."
    );
  }

  return `${lines.join("\n")}\n`;
}

// `gforge settings` prints the current state; --no-autoupdate / --autoupdate
// change the minor and major tiers together.
export async function runSettingsCommand(args, streams, options = {}) {
  const home = options.home;
  const disable = args.includes("--no-autoupdate");
  const enable = args.includes("--autoupdate");

  if (disable && enable) {
    streams.stderr.write("GForge: --autoupdate and --no-autoupdate cannot be combined.\n");
    return { exitCode: 1 };
  }

  const unknown = args.slice(1).filter((a) => !["--no-autoupdate", "--autoupdate"].includes(a));
  if (unknown.length > 0) {
    streams.stderr.write(`GForge: unknown option for settings: ${unknown.join(", ")}\n`);
    return { exitCode: 1 };
  }

  try {
    if (disable || enable) {
      const value = Boolean(enable);
      await (options.writeAutoUpdateSettings ?? writeAutoUpdateSettings)({ minor: value, major: value }, home);
      streams.stdout.write(
        value
          ? "GForge: auto-update enabled for minor and major versions.\n"
          : "GForge: auto-update disabled for minor and major versions.\n" +
            "        Patch updates still install automatically - that is where security fixes ship.\n"
      );
    }

    const resolved = resolveAutoUpdateSettings({
      fileContent: await (options.readSettingsFile ?? readSettingsFile)(home),
      env: options.env ?? process.env
    });
    streams.stdout.write(`\n${formatAutoUpdateSettings(resolved, settingsPath(home))}`);
    return { exitCode: 0 };
  } catch (error) {
    streams.stderr.write(`GForge settings failed\n\n${error?.message ?? error}\n`);
    return { exitCode: 1 };
  }
}
