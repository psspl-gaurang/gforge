import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rename, rmdir, stat, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { detectEnvironment } from "./environment.js";
import { VERSION } from "./metadata.js";
import {
  getEffectiveHooksPath,
  getGlobalHooksPath,
  getRepoGitDir,
  setGlobalHooksPath,
  unsetGlobalHooksPath
} from "./git-config.js";
import {
  MANAGED_FILE_NAMES,
  PRE_COMMIT_FILE_NAME,
  SCANNER_FILE_NAME,
  getManagedFiles,
  getScannerContent,
  resolveHooksDirectory,
  resolveManagedDirectory,
  resolvePreCommitPath,
  resolveScannerPath,
  resolveStatePath
} from "./hooks.js";

// core.hooksPath was added in git 2.9. An older git accepts and stores the
// config key unconditionally (git happily persists config keys it doesn't act
// on) but never consults it when running hooks - install/verify would both
// report success while the scanner silently never runs on any commit.
const MIN_GIT_VERSION_FOR_HOOKS_PATH = [2, 9, 0];

// Tolerates platform-specific suffixes on `git --version` output (e.g.
// "2.39.2 (Apple Git-143)" on macOS, "2.34.1.windows.1" on Windows) by only
// reading the leading numeric run.
function parseGitVersionParts(version) {
  const match = String(version ?? "").match(/^(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3] ?? 0)];
}

// Unparseable versions fail closed (treated as not meeting the minimum)
// rather than silently assuming support.
function meetsMinimumGitVersion(version, minimum) {
  const parts = parseGitVersionParts(version);
  if (!parts) return false;
  for (let i = 0; i < minimum.length; i += 1) {
    const actual = parts[i] ?? 0;
    const required = minimum[i];
    if (actual !== required) return actual > required;
  }
  return true;
}

function describeGitTooOld(version) {
  return (
    `Git ${version} does not support core.hooksPath (added in git 2.9) - ` +
    "hooks would silently never run even though config reports success. Upgrade git."
  );
}

export async function installManagedHooks(options = {}) {
  const environment = options.environment ?? (await detectEnvironment(options));
  const execFileFn = options.execFile;
  const preflight = validateInstallPreflight(environment);

  if (preflight.length > 0) {
    return {
      ok: false,
      command: "install",
      exitCode: 1,
      hooksDirectory: null,
      messages: preflight
    };
  }

  const homePath = environment.home.path;
  const nodePath = options.nodePath ?? process.execPath;
  const managedDirectory = resolveManagedDirectory(homePath);
  const hooksDirectory = resolveHooksDirectory(homePath);
  const statePath = resolveStatePath(homePath);
  const previousHooksPath = await getGlobalHooksPath(execFileFn);

  await mkdir(hooksDirectory, { recursive: true, mode: 0o700 });
  await writeManagedFiles(hooksDirectory, nodePath);
  await writeInstallState(statePath, hooksDirectory, previousHooksPath, nodePath);
  await setGlobalHooksPath(hooksDirectory, execFileFn);

  return {
    ok: true,
    command: "install",
    exitCode: 0,
    hooksDirectory,
    managedDirectory,
    messages: [
      `Installed managed hooks in ${hooksDirectory}`,
      `Configured global core.hooksPath to ${hooksDirectory}`
    ]
  };
}

export async function updateManagedHooks(options = {}) {
  const result = await installManagedHooks(options);

  if (!result.ok) {
    return {
      ...result,
      command: "update"
    };
  }

  return {
    ...result,
    command: "update",
    messages: [
      `Updated managed hooks in ${result.hooksDirectory}`,
      `Configured global core.hooksPath to ${result.hooksDirectory}`
    ]
  };
}

export async function uninstallManagedHooks(options = {}) {
  const environment = options.environment ?? (await detectEnvironment(options));
  const execFileFn = options.execFile;
  const preflight = validateUninstallPreflight(environment);

  if (preflight.length > 0) {
    return {
      ok: false,
      command: "uninstall",
      exitCode: 1,
      hooksDirectory: null,
      messages: preflight
    };
  }

  const homePath = environment.home.path;
  const managedDirectory = resolveManagedDirectory(homePath);
  const hooksDirectory = resolveHooksDirectory(homePath);
  const statePath = resolveStatePath(homePath);
  const { state, corrupt } = await readStateFile(statePath);

  // getGlobalHooksPath() already distinguishes "genuinely not configured"
  // (returns null) from an unexpected read failure (throws) - do NOT flatten
  // that back into null here the way the read-only verify path safely can.
  // If the read fails for any transient reason while the real gitconfig
  // value is still core.hooksPath=<managed dir>, treating it as "not
  // configured" would skip the restore/unset below and then still delete the
  // managed hook files - leaving global core.hooksPath silently pointed at a
  // now-deleted directory, disabling every git hook on the machine (issue #40).
  let configuredHooksPath;
  try {
    configuredHooksPath = await getGlobalHooksPath(execFileFn);
  } catch (error) {
    return {
      ok: false,
      command: "uninstall",
      exitCode: 1,
      hooksDirectory,
      messages: [
        `Could not read the current global core.hooksPath (${error?.message ?? error}); aborting without changing anything, to avoid leaving a stale hooksPath pointed at deleted files`
      ]
    };
  }
  const messages = [];

  if (configuredHooksPath === hooksDirectory) {
    if (state?.previousCoreHooksPath) {
      await setGlobalHooksPath(state.previousCoreHooksPath, execFileFn);
      messages.push(`Restored global core.hooksPath to ${state.previousCoreHooksPath}`);
    } else {
      await unsetGlobalHooksPath(execFileFn);
      messages.push(
        corrupt
          ? "Unset global core.hooksPath; GForge state file was unreadable so no prior value could be restored"
          : "Removed global core.hooksPath managed by GForge"
      );
    }
  } else {
    messages.push(
      configuredHooksPath
        ? `Skipped core.hooksPath restore because it points to ${configuredHooksPath}`
        : "Skipped core.hooksPath restore because it is not configured"
    );
  }

  await removeManagedFiles(hooksDirectory, statePath);
  const removedHooksDirectory = await removeEmptyDirectory(hooksDirectory);
  const removedManagedDirectory = await removeEmptyDirectory(managedDirectory);

  messages.push("Removed GForge-owned hook and state files");

  if (!removedHooksDirectory || !removedManagedDirectory) {
    messages.push("Left non-empty GForge directories in place");
  }

  return {
    ok: true,
    command: "uninstall",
    exitCode: 0,
    hooksDirectory,
    managedDirectory,
    messages
  };
}

export async function verifyManagedHooks(options = {}) {
  const environment = options.environment ?? (await detectEnvironment(options));
  const execFileFn = options.execFile;
  const checks = [];

  if (!environment.home.present) {
    return {
      hooksDirectory: null,
      checks: [
        {
          status: "FAIL",
          label: "hooks-directory",
          detail: "home directory not detected"
        }
      ]
    };
  }

  const hooksDirectory = resolveHooksDirectory(environment.home.path);
  const configuredHooksPath = await safeGetGlobalHooksPath(execFileFn);

  if (environment.git.available && !meetsMinimumGitVersion(environment.git.version, MIN_GIT_VERSION_FOR_HOOKS_PATH)) {
    // Surfaced even when hooks-path below reports PASS: git accepts and
    // stores core.hooksPath unconditionally on older versions, but never
    // consults it, so a passing config check alone does not mean hooks run.
    checks.push({
      status: "FAIL",
      label: "git-version",
      detail: describeGitTooOld(environment.git.version)
    });
  }

  checks.push({
    status: configuredHooksPath === hooksDirectory ? "PASS" : "FAIL",
    label: "hooks-path",
    detail: configuredHooksPath
      ? `core.hooksPath is ${configuredHooksPath}`
      : "core.hooksPath is not configured"
  });

  const effectiveHooksPath = await safeGetEffectiveHooksPath(execFileFn);
  if (effectiveHooksPath && effectiveHooksPath !== hooksDirectory) {
    checks.push({
      // Blocking: this is not advisory. Scanning is entirely inactive here, so
      // `gforge verify` must not report success — a CI gate built on its exit
      // code would otherwise treat an unprotected repository as healthy
      // (issue #42). Contrast with classic-hook-shadowed below, which warns
      // that the user's OWN legacy hook is dormant while GForge itself runs.
      blocking: true,
      status: "WARN",
      label: "effective-hooks-path",
      detail: `core.hooksPath resolves to ${effectiveHooksPath} here; a repository-local or system override shadows the managed hooks, so GForge will not run in this repository`
    });
  } else if (effectiveHooksPath === hooksDirectory) {
    // The mirror-image case: GForge IS what's actually active here, which
    // means git no longer looks in this repository's own hooks/ directory
    // at all - a classic hand-written script left there goes silently
    // dormant, for every hook type, not just pre-commit (issue #41).
    const classicHook = await checkClassicHookShadowed(execFileFn);
    if (classicHook) checks.push(classicHook);
  }

  const directoryCheck = await checkDirectory(hooksDirectory);

  // Nothing is installed at all. Running the per-file checks here produces four
  // cascading FAILs for a single root cause, and one of them ("engine not found
  // - run `gforge update`") gives actively wrong advice: update refreshes an
  // existing install, it is not how you set one up. Say it once, correctly, and
  // name the cause that produces this state silently - `npm install
  // --ignore-scripts` skips the postinstall step that installs the hooks, so
  // the package is on PATH while nothing is ever scanned (issue #53).
  if (directoryCheck.missing) {
    checks.push({
      status: "FAIL",
      label: "not-installed",
      detail:
        `no managed hooks at ${hooksDirectory} - GForge is not installed, so no commit is being scanned. ` +
        "If it was installed with `npm install --ignore-scripts`, the postinstall step that installs the " +
        "hooks never ran. Run `gforge install` to set them up."
    });
    return { hooksDirectory, checks };
  }

  checks.push(directoryCheck);

  const scannerPath = resolveScannerPath(environment.home.path);
  checks.push(await checkScannerContent(scannerPath));

  const preCommitPath = resolvePreCommitPath(environment.home.path);
  checks.push(await checkPreCommitShim(preCommitPath));
  checks.push(await checkHookExecutable(PRE_COMMIT_FILE_NAME, preCommitPath, environment.platform.name));

  return {
    hooksDirectory,
    checks
  };
}

// Compares the installed engine against the current package's engine. A mismatch
// almost always means the package was upgraded but the hook was not refreshed,
// so the message points straight at the fix.
async function checkScannerContent(scannerPath) {
  const expected = getScannerContent();
  try {
    const actual = await readFile(scannerPath, "utf8");
    if (actual === expected) {
      return { status: "PASS", label: `${SCANNER_FILE_NAME}-content`, detail: "managed content matches" };
    }
    return {
      status: "FAIL",
      label: `${SCANNER_FILE_NAME}-content`,
      detail: "installed engine is stale or modified - run `gforge update`"
    };
  } catch {
    return {
      status: "FAIL",
      label: `${SCANNER_FILE_NAME}-content`,
      detail: "engine not found - run `gforge update`"
    };
  }
}

// The pre-commit shim embeds a machine-specific Node path, so verify checks its
// structure (present and delegating to the managed scanner) rather than an
// exact byte match.
async function checkPreCommitShim(preCommitPath) {
  try {
    const content = await readFile(preCommitPath, "utf8");
    const wired = content.includes(SCANNER_FILE_NAME) && content.includes("exec");
    return {
      status: wired ? "PASS" : "FAIL",
      label: `${PRE_COMMIT_FILE_NAME}-content`,
      detail: wired ? "delegates to managed scanner" : "does not delegate to managed scanner"
    };
  } catch {
    return {
      status: "FAIL",
      label: `${PRE_COMMIT_FILE_NAME}-content`,
      detail: `${preCommitPath} not found`
    };
  }
}

export function formatInstallResult(result) {
  const command = result.command ?? "install";
  const header = result.ok ? `GForge ${command} complete` : `GForge ${command} failed`;
  return `${[header, "", ...result.messages].join("\n")}\n`;
}

// Exported so the CLI can run it BEFORE any network work: there is no point
// asking the registry for a new version on a machine that cannot install one
// (issue #32).
export function validateInstallPreflight(environment) {
  const messages = [];

  if (!environment.platform.supported) {
    messages.push(`Unsupported platform: ${environment.platform.name}`);
  }

  if (!environment.home.present) {
    messages.push("Home directory not detected.");
  }

  if (!environment.git.available) {
    messages.push("Git is required but was not found.");
  } else if (!meetsMinimumGitVersion(environment.git.version, MIN_GIT_VERSION_FOR_HOOKS_PATH)) {
    messages.push(describeGitTooOld(environment.git.version));
  }

  return messages;
}

function validateUninstallPreflight(environment) {
  const messages = [];

  if (!environment.home.present) {
    messages.push("Home directory not detected.");
  }

  if (!environment.git.available) {
    messages.push("Git is required but was not found.");
  }

  return messages;
}

async function writeManagedFiles(hooksDirectory, nodePath) {
  for (const file of getManagedFiles(nodePath)) {
    await writeFileAtomic(join(hooksDirectory, file.name), file.content, file.mode);
  }
}

// Write via a sibling temp file and rename into place so readers (a concurrent
// git commit, or a crash mid-write) never observe a truncated or empty hook.
//
// The temp name must be unique per call. A fixed `${filePath}.gforge-tmp` meant
// two concurrent installs — two terminals, or several packages triggering
// postinstall at once in a monorepo — wrote to the SAME temp file and then both
// renamed it: the result was byte-spliced from both writers, and whichever lost
// the race got an uncaught ENOENT because the other had already renamed the
// file away (issue #39). Reproduced at 60/60 iterations before this change.
//
// rename(2) is atomic and replaces the destination, so with distinct temp paths
// concurrent writers are safe: each renames its own complete file and the last
// one wins, rather than the two being interleaved.
async function writeFileAtomic(filePath, content, mode) {
  // Keeps the .gforge-tmp suffix so leftover debris is still identifiable.
  const tempPath = `${filePath}.${process.pid}-${randomUUID()}.gforge-tmp`;
  try {
    await writeFile(tempPath, content, { mode });
    await chmod(tempPath, mode);
    await rename(tempPath, filePath);
  } catch (error) {
    // Never leave a partial temp file behind on failure - it would otherwise
    // accumulate silently in the user's ~/.gforge/hooks directory forever.
    await unlink(tempPath).catch(() => {});
    throw error;
  }
}

async function removeManagedFiles(hooksDirectory, statePath) {
  for (const name of MANAGED_FILE_NAMES) {
    await removeFile(join(hooksDirectory, name));
  }

  await removeFile(statePath);
}

async function removeFile(filePath) {
  try {
    await unlink(filePath);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
}

async function removeEmptyDirectory(directoryPath) {
  try {
    await rmdir(directoryPath);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return true;
    }

    if (error?.code === "ENOTEMPTY" || error?.code === "EEXIST") {
      return false;
    }

    throw error;
  }
}

async function writeInstallState(statePath, hooksDirectory, currentHooksPath, nodePath) {
  const { corrupt, state: existingState } = await readStateFile(statePath);

  if (corrupt) {
    // Never silently discard an unreadable backup; preserve it for recovery
    // rather than overwriting the only record of the original hooks path.
    await preserveCorruptState(statePath);
  }

  let previousCoreHooksPath;
  if (existingState && "previousCoreHooksPath" in existingState) {
    // A prior install already recorded the original config (including a
    // deliberate null meaning "was unset"); never overwrite that backup.
    previousCoreHooksPath = existingState.previousCoreHooksPath;
  } else if (currentHooksPath && currentHooksPath !== hooksDirectory) {
    previousCoreHooksPath = currentHooksPath;
  } else {
    previousCoreHooksPath = null;
  }

  const state = {
    version: 2,
    managedBy: "gforge",
    gforgeVersion: VERSION,
    hooksDirectory,
    nodePath: nodePath ?? null,
    previousCoreHooksPath
  };

  await writeFileAtomic(statePath, `${JSON.stringify(state, null, 2)}\n`, 0o600);
}

// Distinguishes a genuinely absent state file (fresh install) from a present
// but unparseable one, so a corrupt file is not mistaken for "no prior state".
async function readStateFile(statePath) {
  let raw;
  try {
    raw = await readFile(statePath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      return { present: false, corrupt: false, state: null };
    }

    throw error;
  }

  try {
    return { present: true, corrupt: false, state: JSON.parse(raw) };
  } catch {
    return { present: true, corrupt: true, state: null };
  }
}

async function preserveCorruptState(statePath) {
  try {
    await rename(statePath, `${statePath}.corrupt`);
  } catch {
    // Best effort only: if it cannot be preserved, the fresh write proceeds.
  }
}

async function safeGetGlobalHooksPath(execFileFn) {
  try {
    return await getGlobalHooksPath(execFileFn);
  } catch {
    return null;
  }
}

async function safeGetEffectiveHooksPath(execFileFn) {
  try {
    return await getEffectiveHooksPath(execFileFn);
  } catch {
    return null;
  }
}

// A classic hand-written .git/hooks/pre-commit script goes silently dormant
// once GForge's global core.hooksPath is what actually resolves here — git
// only ever consults ONE hooksPath location, and it is no longer this
// repository's own hooks/ directory (issue #41). Nothing to check outside a
// git repository; never fatal, since the developer may not even have relied
// on it, but they deserve to know it stopped running.
async function checkClassicHookShadowed(execFileFn) {
  const gitDir = await getRepoGitDir(execFileFn);
  if (!gitDir) return null;

  const classicPath = join(gitDir, "hooks", PRE_COMMIT_FILE_NAME);
  try {
    const classicStat = await stat(classicPath);
    if (!(classicStat.mode & 0o111)) return null; // present but not executable - git would never have run it either
  } catch {
    return null;
  }

  return {
    status: "WARN",
    label: "classic-hook-shadowed",
    detail:
      `${classicPath} is executable but dormant — GForge's global core.hooksPath means git no longer looks ` +
      "in this repository's own hooks/ directory, for any hook type, not just pre-commit"
  };
}

async function checkDirectory(hooksDirectory) {
  try {
    const directoryStat = await stat(hooksDirectory);
    return {
      status: directoryStat.isDirectory() ? "PASS" : "FAIL",
      label: "hooks-directory",
      detail: hooksDirectory
    };
  } catch {
    return {
      // Distinguishes "nothing is installed" from "something is wrong with what
      // is installed" - the two need different remedies (see issue #53).
      missing: true,
      status: "FAIL",
      label: "hooks-directory",
      detail: `${hooksDirectory} not found`
    };
  }
}

async function checkHookExecutable(name, hookPath, platform) {
  if (platform === "win32") {
    return {
      status: "PASS",
      label: `${name}-executable`,
      detail: "not required on win32"
    };
  }

  try {
    const hookStat = await stat(hookPath);
    const executable = Boolean(hookStat.mode & 0o111);
    return {
      status: executable ? "PASS" : "FAIL",
      label: `${name}-executable`,
      detail: executable ? "executable" : "not executable"
    };
  } catch {
    return {
      status: "FAIL",
      label: `${name}-executable`,
      detail: `${hookPath} not found`
    };
  }
}
