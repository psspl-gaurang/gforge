// npm self-update helpers: query the registry for the latest published version
// and upgrade the globally installed package. All network/child-process calls are
// injectable so the CLI logic can be unit-tested without touching npm.

import { execFile, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export const PACKAGE_NAME = "gforge";

// On Windows the global npm is `npm.cmd`, which execFile/spawn cannot launch
// without a shell — so npm calls must run through the shell there. Elsewhere we
// avoid the shell. Version strings are validated before interpolation so there
// is no shell-injection surface.
const NPM_VIA_SHELL = process.platform === "win32";
// Every npm call runs from the user's home directory, never from wherever the
// caller happened to be. With shell:true on Windows, cmd.exe resolves an
// unqualified command against the CURRENT DIRECTORY before PATH - so a
// repository containing its own npm.cmd (untracked is enough) would have that
// file run instead of the real npm, during a command the developer thinks is
// just an upgrade (issue #78).
const NPM_CWD = homedir();
const SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

// Numeric compare of X.Y.Z (prerelease/build metadata ignored).
export function compareVersions(a, b) {
  const pa = String(a).split(".").map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i += 1) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x > y) return 1;
    if (x < y) return -1;
  }
  return 0;
}

export function isNewer(latest, current) {
  return compareVersions(latest, current) > 0;
}

// Reads the cache written by the hook's background check and returns a one-line
// notice if a newer version is available, else null. Never throws.
export function readCachedUpdateNotice(currentVersion) {
  try {
    const cache = JSON.parse(readFileSync(join(homedir(), ".gforge", "update-check.json"), "utf8"));
    if (cache && cache.latest && isNewer(cache.latest, currentVersion)) {
      return `gforge v${cache.latest} is available (you have v${currentVersion}). Run: gforge update`;
    }
  } catch {
    // no cache yet / unreadable — no notice
  }
  return null;
}

// Best-effort: returns the latest published version, or null if offline / npm
// unavailable / anything unexpected. Never throws.
export async function getLatestVersion(options = {}) {
  const exec = options.execFile ?? execFileAsync;
  try {
    const { stdout } = await exec("npm", ["view", PACKAGE_NAME, "version"], {
      cwd: NPM_CWD,
      timeout: options.timeoutMs ?? 8000,
      shell: NPM_VIA_SHELL
    });
    const value = String(stdout).trim();
    return SEMVER.test(value) ? value : null;
  } catch {
    return null;
  }
}

async function getGlobalBinPath(options = {}) {
  const exec = options.execFile ?? execFileAsync;
  try {
    const { stdout } = await exec("npm", ["root", "-g"], {
      cwd: NPM_CWD,
      timeout: options.timeoutMs ?? 8000,
      shell: NPM_VIA_SHELL
    });
    const root = String(stdout).trim();
    return root ? join(root, PACKAGE_NAME, "bin", "gforge.js") : null;
  } catch {
    return null;
  }
}

// Upgrade the global package to `version`, then re-exec the freshly installed
// binary to finish the requested command with the NEW code (guarded against
// recursion via GFORGE_NO_SELF_UPDATE). Returns { ok, ... }; never throws.
export async function performSelfUpgrade(command, version, options = {}) {
  // `version` is only used to decide/report; the install target is the constant
  // `${PACKAGE_NAME}@latest` (npm's `latest` dist-tag IS what getLatestVersion
  // reads), so no registry-derived string is ever interpolated into the command.
  if (!SEMVER.test(String(version))) {
    return { ok: false, error: `refusing to upgrade to unexpected version "${version}"` };
  }
  const run = options.spawnSync ?? spawnSync;

  // Unlike the two metadata calls above (bounded at 8s), an actual package
  // install is expected to take longer, so it gets its own, longer bound
  // rather than sharing timeoutMs. Either way, a hung or extremely slow
  // registry/proxy/filesystem must not block `gforge install`/`update`
  // indefinitely.
  const installTimeoutMs = options.installTimeoutMs ?? 60000;
  const install = run("npm", ["install", "-g", `${PACKAGE_NAME}@latest`], {
    cwd: NPM_CWD,
    stdio: "inherit",
    shell: NPM_VIA_SHELL,
    timeout: installTimeoutMs
  });
  if (install?.error?.code === "ETIMEDOUT") {
    return { ok: false, error: `npm install -g ${PACKAGE_NAME}@latest timed out after ${installTimeoutMs}ms` };
  }
  if (!install || install.status !== 0) {
    return { ok: false, error: `npm install -g ${PACKAGE_NAME}@latest exited with status ${install ? install.status : "unknown"}` };
  }

  const bin = options.binPath ?? (await getGlobalBinPath(options));
  if (!bin) {
    // Could not locate the new binary. When GForge was already active the
    // postinstall step will have refreshed the hook, so treat as success.
    return { ok: true, reexeced: false };
  }

  const node = options.nodePath ?? process.execPath;
  const child = run(node, [bin, command], {
    stdio: "inherit",
    env: { ...process.env, GFORGE_NO_SELF_UPDATE: "1" }
  });
  return { ok: !!child && child.status === 0, reexeced: true, status: child ? child.status : null };
}
