// `gforge probe`: an opt-in check that the installed GForge hook actually
// blocks a commit. `gforge verify` only reads files and config; this command
// is the one that runs Git. It never touches the caller's repository, global
// Git config, or ~/.gforge.
//
// The installed pre-commit and gforge-scan.mjs must be byte-for-byte the
// current GForge files, and the hooks directory must not contain any other
// executable. Only those two files are copied into a disposable tree. Git
// then runs with an allowlisted environment so a signing program, filter,
// alias, gitleaks binary, or update install from the caller's environment
// cannot run. A pass covers that one copy, not every repository or GUI client
// (issue #131).

import { spawn, spawnSync } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readdir, readFile, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import { detectEnvironment } from "./environment.js";
import {
  MANAGED_FILE_NAMES,
  PRE_COMMIT_FILE_NAME,
  SCANNER_FILE_NAME,
  getManagedFiles,
  getScannerContent,
  isGforgeManagedContent,
  resolveHooksDirectory,
  resolvePreCommitPath,
  resolveScannerPath,
  resolveStatePath
} from "./hooks.js";
import { hookInvokesScanner, verifyManagedHooks } from "./installer.js";

// Not a real credential. Printed nowhere: reports are scrubbed of this value.
export const PROBE_SYNTHETIC_SECRET = "psspl@443e-probe-synthetic";

const CLEAN_FILE = "notes.txt";
const SECRET_FILE = "config.txt";
const CLEAN_CONTENT = "export const ready = true;\n";
const SECRET_CONTENT = `DB_PASS=${PROBE_SYNTHETIC_SECRET}\n`;
const CLEAN_MESSAGE = "gforge probe clean";
const SECRET_MESSAGE = "gforge probe synthetic";
const PROBE_DIR_PREFIX = "gforge-probe-";
const OUTPUT_LIMIT = 64 * 1024;

const SCOPE_LINES = [
  "Scope: one disposable repository, one clean file, one synthetic credential, the copied verified hook, and this process environment.",
  "A successful probe does not prove every repository or GUI environment is protected.",
  "It does not prove other repositories, a GUI client, a symlinked core.hooksPath, a local or system hooks override, custom rules, or gitleaks.",
  "The gitleaks layer was not exercised.",
  "Custom rules were not loaded."
];

export function redactProbeText(text, secret = PROBE_SYNTHETIC_SECRET) {
  return String(text ?? "").split(secret).join("[redacted]");
}

export function formatProtectionProbeReport(outcome) {
  const scrub = (value) => redactProbeText(value);
  const lines = ["GForge protection probe", ""];
  lines.push(`result: ${outcome.result}`);
  if (outcome.reason) lines.push(`reason: ${scrub(outcome.reason)}`);
  if (outcome.platform) lines.push(`platform: ${scrub(outcome.platform)}`);
  if (outcome.clean) lines.push(`clean: ${scrub(outcome.clean)}`);
  if (outcome.secret) lines.push(`secret: ${scrub(outcome.secret)}`);
  if (outcome.worktree) lines.push(`worktree: ${scrub(outcome.worktree)}`);
  if (outcome.commit) lines.push(`commit: ${scrub(outcome.commit)}`);
  if (outcome.detail) lines.push(`detail: ${scrub(outcome.detail)}`);
  if (outcome.warnings?.length) {
    lines.push("");
    lines.push("configuration:");
    for (const warning of outcome.warnings) lines.push(scrub(warning));
  }
  if (outcome.hookOutput) {
    lines.push("");
    lines.push("hook-output:");
    lines.push(scrub(outcome.hookOutput));
  }
  lines.push("");
  lines.push(...SCOPE_LINES);
  return `${lines.join("\n")}\n`;
}

function textOf(run) {
  return `${run?.stdout ?? ""}\n${run?.stderr ?? ""}\n${run?.error ?? ""}`;
}

function describeRun(run, blocked) {
  if (!run) return "not run";
  if (run.signal) return `signal ${run.signal}`;
  if (typeof run.status !== "number") return "null status";
  if (run.status === 0) return "allowed (exit 0)";
  if (blocked) return `blocked (exit ${run.status})`;
  return `exit ${run.status}`;
}

function hookOutputOf(clean, secret) {
  const text = redactProbeText(`${textOf(clean)}\n${textOf(secret)}`).trim();
  if (!text) return "";
  return text.length > 1500 ? `${text.slice(0, 1500)}\n[truncated]` : text;
}

// Distinct, visible outcomes for the two controls. A non-zero secret commit
// is not enough: a missing runtime and a scanner crash also exit non-zero,
// and calling either one "protected" would hide a hook that never scanned.
export function classifyControls(clean, secret) {
  const cleanText = textOf(clean);
  const secretText = textOf(secret);
  const all = `${cleanText}\n${secretText}`;
  const summary = {
    clean: describeRun(clean, false),
    secret: describeRun(secret, false)
  };

  if (all.includes("no Node.js runtime found to scan for secrets")) {
    return { ...summary, result: "missing-runtime", detail: "no Node.js runtime found to scan for secrets" };
  }
  if (all.includes("secret scan could not complete")) {
    return { ...summary, result: "scan-incomplete", detail: "secret scan could not complete" };
  }

  const signal = clean?.signal || secret?.signal;
  if (signal) {
    return { ...summary, result: "signal", detail: `git exited from signal ${signal}` };
  }
  if (typeof clean?.status !== "number" || typeof secret?.status !== "number") {
    return { ...summary, result: "null-status", detail: "git returned a null status" };
  }
  if (cleanText.includes(PROBE_SYNTHETIC_SECRET) || secretText.includes(PROBE_SYNTHETIC_SECRET)) {
    return { ...summary, result: "unexpected-status", detail: "hook output included the synthetic credential" };
  }

  const secretBlocked =
    secret.status !== 0 &&
    secretText.includes("COMMIT BLOCKED") &&
    secretText.includes("Potential secrets detected");
  if (clean.status === 0 && secretBlocked) {
    return {
      clean: describeRun(clean, false),
      secret: describeRun(secret, true),
      result: "protected",
      detail: "the clean file was allowed and the synthetic credential was blocked (COMMIT BLOCKED)"
    };
  }
  if (clean.status === 0 && secret.status === 0) {
    return {
      ...summary,
      result: "inert-dispatch",
      detail: "both commits were allowed; the hook did not block the synthetic credential"
    };
  }
  if (clean.status !== 0 && secret.status !== 0) {
    return {
      ...summary,
      result: "both-blocked",
      detail: "both commits were rejected; the clean file was not allowed"
    };
  }
  return {
    ...summary,
    result: "unexpected-status",
    detail: `clean exit ${clean.status}; secret exit ${secret.status}`
  };
}

function refuse(reason, detail, platform, warnings = []) {
  return { ok: false, reason, detail, platform, warnings };
}

function configurationWarnings(checks) {
  const warnings = [];
  if (!checks) return warnings;
  for (const check of checks) {
    if (check.status === "PASS") continue;
    if (check.label === "git-version" || check.label === "not-installed") continue;
    if (String(check.label).endsWith("-content")) continue;
    warnings.push(`${check.status} ${check.label}: ${check.detail}`);
  }
  const hooksPath = checks.find((check) => check.label === "hooks-path");
  const effective = checks.find((check) => check.label === "effective-hooks-path");
  if (effective || (hooksPath && hooksPath.status !== "PASS")) {
    warnings.push("This probe copied the verified hook and did not execute any other hooks path.");
  }
  return warnings;
}

async function readNodePath(home) {
  try {
    const state = JSON.parse(await readFile(resolveStatePath(home), "utf8"));
    return typeof state?.nodePath === "string" && state.nodePath ? state.nodePath : null;
  } catch {
    return null;
  }
}

async function findExtraExecutables(hooksDirectory) {
  const entries = await readdir(hooksDirectory, { withFileTypes: true });
  const extras = [];
  for (const entry of entries) {
    if (MANAGED_FILE_NAMES.includes(entry.name)) continue;
    if (entry.isDirectory()) continue;
    const full = join(hooksDirectory, entry.name);
    try {
      const info = await stat(full);
      if (info.isFile() && (info.mode & 0o111) !== 0) extras.push(entry.name.replace(/[\r\n]+/g, " "));
    } catch {
      // Unreadable or a dangling link: not something this probe can prove is inert.
      extras.push(entry.name.replace(/[\r\n]+/g, " "));
    }
  }
  return extras;
}

async function assessInstallation(options) {
  const environment = options.environment ?? (await detectEnvironment(options));
  const platform = `${environment.platform?.name ?? ""} ${environment.platform?.arch ?? ""}`.trim();

  if (!environment.platform?.supported) {
    return refuse("unsupported-platform", `unsupported platform: ${environment.platform?.name ?? "unknown"}`, platform);
  }
  if (!environment.home?.present || !environment.home.path) {
    return refuse("home-missing", "home directory not detected", platform);
  }
  if (!environment.git?.available) {
    return refuse("git-missing", "git not found", platform);
  }

  let managed;
  try {
    managed = await verifyManagedHooks({ ...options, environment });
  } catch (error) {
    return refuse("probe-error", error?.message ?? String(error), platform);
  }

  const warnings = configurationWarnings(managed.checks);
  const gitVersion = managed.checks?.find((check) => check.label === "git-version");
  if (gitVersion?.status === "FAIL") {
    return refuse("git-too-old", gitVersion.detail, platform, warnings);
  }

  const home = environment.home.path;
  const hooksDirectory = resolveHooksDirectory(home);
  try {
    await readdir(hooksDirectory);
  } catch {
    const notInstalled = managed.checks?.find((check) => check.label === "not-installed");
    return refuse(
      "not-installed",
      notInstalled?.detail ?? `no managed hooks at ${hooksDirectory}`,
      platform,
      warnings
    );
  }

  const expectedScanner = getScannerContent();
  let actualScanner;
  try {
    actualScanner = await readFile(resolveScannerPath(home), "utf8");
  } catch {
    return refuse("engine-mismatch", "engine not found", platform, warnings);
  }
  if (actualScanner !== expectedScanner) {
    const owned = isGforgeManagedContent(SCANNER_FILE_NAME, actualScanner);
    return refuse(
      "engine-mismatch",
      owned ? "installed engine is stale or modified" : "installed engine is not a GForge-owned file",
      platform,
      warnings
    );
  }

  const nodePath = await readNodePath(home);
  if (!nodePath) {
    return refuse(
      "unverified-shim",
      "install state has no recorded node path, so the hook cannot be verified",
      platform,
      warnings
    );
  }

  const expectedShim = getManagedFiles(nodePath).find((file) => file.name === PRE_COMMIT_FILE_NAME)?.content;
  let actualShim;
  try {
    actualShim = await readFile(resolvePreCommitPath(home), "utf8");
  } catch {
    return refuse("hook-mismatch", "pre-commit not found", platform, warnings);
  }
  if (actualShim !== expectedShim) {
    if (!isGforgeManagedContent(PRE_COMMIT_FILE_NAME, actualShim)) {
      return refuse("hook-mismatch", "pre-commit is not a GForge-owned file; refusing to execute it", platform, warnings);
    }
    if (!hookInvokesScanner(actualShim)) {
      return refuse("hook-neutered", "pre-commit does not run the scanner; refusing to execute it", platform, warnings);
    }
    return refuse("hook-mismatch", "pre-commit has been modified or is stale; refusing to execute it", platform, warnings);
  }

  let extras = [];
  try {
    extras = await findExtraExecutables(hooksDirectory);
  } catch (error) {
    return refuse("probe-error", error?.message ?? String(error), platform, warnings);
  }
  if (extras.length > 0) {
    return refuse(
      "extra-executable",
      `refusing to execute extra executable hook: ${extras.join(", ")}`,
      platform,
      warnings
    );
  }

  return {
    ok: true,
    environment,
    platform,
    warnings,
    home,
    hooksDirectory,
    nodePath,
    expectedScanner,
    expectedShim
  };
}

function systemShell() {
  if (existsSync("/bin/sh")) return "/bin/sh";
  if (existsSync("/usr/bin/sh")) return "/usr/bin/sh";
  return null;
}

function lookupBinary(name, pathEnv) {
  const shell = systemShell();
  if (!shell) return null;
  const result = spawnSync(shell, ["-c", 'command -v "$1"', "lookup", name], {
    env: { PATH: pathEnv ?? "" },
    encoding: "utf8"
  });
  const found = String(result.stdout ?? "").trim();
  return result.status === 0 && found ? found : null;
}

export function runGitCommand(args, { cwd, env, onChild, spawnImpl = spawn } = {}) {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    const child = spawnImpl("git", args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    onChild?.(child);
    const finish = (result) => {
      if (settled) return;
      settled = true;
      onChild?.(null);
      resolve(result);
    };
    child.stdout?.on("data", (chunk) => {
      if (stdout.length < OUTPUT_LIMIT) stdout += chunk.toString("utf8");
    });
    child.stderr?.on("data", (chunk) => {
      if (stderr.length < OUTPUT_LIMIT) stderr += chunk.toString("utf8");
    });
    child.on("error", (error) => {
      finish({ status: null, signal: null, stdout, stderr, error: error?.message ?? String(error) });
    });
    child.on("close", (status, signal) => {
      finish({ status, signal, stdout, stderr });
    });
  });
}

function probeRootNameOk(root) {
  const name = basename(String(root ?? ""));
  return name.startsWith(PROBE_DIR_PREFIX) && name.length > PROBE_DIR_PREFIX.length;
}

export async function removeProbeDirectory(root) {
  if (!root) return;
  if (!probeRootNameOk(root)) {
    throw new Error("refusing to remove a directory the probe did not create");
  }
  await rm(root, { recursive: true, force: true });
}

function removeProbeDirectorySync(root) {
  if (!root || !probeRootNameOk(root)) return;
  rmSync(root, { recursive: true, force: true });
}

// Installed only while a disposable tree exists, and removed before the
// function returns. A process-wide handler left in place would steal SIGINT
// from the test runner. The handler deletes that one directory, never a
// prefix match and never ~/.gforge.
export function armProbeCleanup(state) {
  const onSignal = (signal) => {
    const child = state.child;
    if (child && child.exitCode === null && !child.killed) {
      try {
        child.kill("SIGKILL");
      } catch {
        // The child already exited.
      }
    }
    removeProbeDirectorySync(state.root);
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
    process.kill(process.pid, signal);
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  return () => {
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
  };
}

async function createTempRoot(parent) {
  const dir = parent ?? tmpdir();
  await mkdir(dir, { recursive: true });
  return realpath(await mkdtemp(join(dir, PROBE_DIR_PREFIX)));
}

function buildProbeEnvironment({ home, bin, gitconfig, root }) {
  const tmp = join(root, "tmp");
  // Allowlist, not a copy of process.env. Inherited Git config, GFORGE_NODE,
  // npm settings, and registry URLs are how a probe would otherwise run a
  // signing program or phone home.
  return {
    HOME: home,
    USERPROFILE: home,
    PATH: bin,
    GIT_CONFIG_GLOBAL: gitconfig,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
    NO_COLOR: "1",
    LC_ALL: "C",
    TMPDIR: tmp,
    TEMP: tmp,
    TMP: tmp,
    XDG_CONFIG_HOME: join(root, "xdg-config"),
    XDG_DATA_HOME: join(root, "xdg-data"),
    XDG_RUNTIME_DIR: join(root, "xdg-runtime"),
    XDG_CACHE_HOME: join(root, "xdg-cache")
  };
}

function gitFailure(what, result) {
  const output = redactProbeText(`${result?.stderr ?? ""}\n${result?.stdout ?? ""}`).trim().split("\n")[0] ?? "";
  const status = result?.signal ? `signal ${result.signal}` : `exit ${result?.status}`;
  return {
    result: "setup-failed",
    detail: output ? `git ${what} ${status}: ${output}` : `git ${what} ${status}`
  };
}

async function executeProbe(state, assessment, options) {
  const root = state.root;
  const finish = (fields) => ({ platform: assessment.platform, warnings: assessment.warnings, ...fields });
  const home = join(root, "home");
  const bin = join(root, "bin");
  const repo = join(root, "repository");
  const worktree = join(root, "linked-worktree");
  const hooks = join(root, "hooks");
  const gitconfig = join(root, "gitconfig");
  const cachePath = join(home, ".gforge", "update-check.json");

  await mkdir(join(home, ".gforge"), { recursive: true });
  await mkdir(bin, { recursive: true });
  await mkdir(hooks, { recursive: true });
  for (const dir of ["tmp", "xdg-config", "xdg-data", "xdg-runtime", "xdg-cache"]) {
    await mkdir(join(root, dir), { recursive: true });
  }
  await chmod(join(root, "xdg-runtime"), 0o700);

  // Write the bytes we compared, not a second read of the installed files.
  await writeFile(join(hooks, SCANNER_FILE_NAME), assessment.expectedScanner, { mode: 0o644 });
  await writeFile(join(hooks, PRE_COMMIT_FILE_NAME), assessment.expectedShim, { mode: 0o755 });
  await chmod(join(hooks, PRE_COMMIT_FILE_NAME), 0o755);
  const hooksReal = await realpath(hooks);

  // A fresh cache makes updateCacheIsStale() false, so the engine does not
  // spawn the detached __update-check worker (that worker fetches the registry
  // and can run npm install). HOME below is this disposable directory, which
  // is also where the engine reads the cache.
  const cacheBody = `${JSON.stringify({ checkedAt: Date.now() })}\n`;
  await writeFile(cachePath, cacheBody);

  const lookupPath = options.lookupPath ?? process.env.PATH ?? "";
  const gitBin = lookupBinary("git", lookupPath);
  const shBin = lookupBinary("sh", lookupPath);
  const dirnameBin = lookupBinary("dirname", lookupPath);
  if (!gitBin || !shBin || !dirnameBin) {
    return finish({ result: "setup-failed", detail: "could not find git, sh, and dirname on PATH" });
  }
  await symlink(gitBin, join(bin, "git"));
  await symlink(shBin, join(bin, "sh"));
  await symlink(dirnameBin, join(bin, "dirname"));
  if (assessment.nodePath && existsSync(assessment.nodePath)) {
    await symlink(assessment.nodePath, join(bin, "node"));
    if (basename(assessment.nodePath).toLowerCase() === "node.exe") {
      await symlink(assessment.nodePath, join(bin, "node.exe"));
    }
  }

  const env = buildProbeEnvironment({ home, bin, gitconfig, root });
  const runGit = (args, cwd) =>
    (options.runGit ?? runGitCommand)(args, {
      cwd,
      env,
      onChild: (child) => {
        state.child = child;
      }
    });

  const configPairs = [
    ["user.name", "GForge Probe"],
    ["user.email", "probe@example.invalid"],
    ["core.hooksPath", hooksReal],
    ["commit.gpgsign", "false"],
    ["tag.gpgsign", "false"]
  ];
  for (const [key, value] of configPairs) {
    const wrote = await runGit(["config", "--file", gitconfig, key, value], root);
    if (wrote.status !== 0 || wrote.signal) return finish(gitFailure(`config ${key}`, wrote));
  }

  const inited = await runGit(["init", "-q", repo], root);
  if (inited.status !== 0 || inited.signal) return finish(gitFailure("init", inited));

  // An orphan linked worktree needs no scaffolding commit, so the only commits
  // that run the hook are the two controls below. Both run in the worktree,
  // where Git sets a worktree GIT_DIR rather than the main repository's.
  const addedTree = await runGit(
    ["worktree", "add", "--orphan", "-b", "gforge-probe-wt", "--", worktree],
    repo
  );
  if (addedTree.status !== 0 || addedTree.signal) return finish(gitFailure("worktree add", addedTree));

  await writeFile(join(worktree, CLEAN_FILE), CLEAN_CONTENT);
  const cleanAdded = await runGit(["add", "--", CLEAN_FILE], worktree);
  if (cleanAdded.status !== 0 || cleanAdded.signal) return finish(gitFailure("add", cleanAdded));
  const clean = await runGit(["commit", "-m", CLEAN_MESSAGE], worktree);

  // A rejected commit leaves its file staged. Reset before the second control
  // so the clean file cannot make the secret commit fail for the wrong reason.
  const reset = await runGit(["reset", "-q"], worktree);
  if (reset.status !== 0 || reset.signal) return finish(gitFailure("reset", reset));
  if (clean.status !== 0) {
    await rm(join(worktree, CLEAN_FILE), { force: true });
  }

  await writeFile(join(worktree, SECRET_FILE), SECRET_CONTENT);
  const secretAdded = await runGit(["add", "--", SECRET_FILE], worktree);
  if (secretAdded.status !== 0 || secretAdded.signal) return finish(gitFailure("add", secretAdded));
  const secret = await runGit(["commit", "-m", SECRET_MESSAGE], worktree);

  let updateWorkerStarted = false;
  try {
    const cacheAfter = await readFile(cachePath, "utf8");
    if (cacheAfter !== cacheBody) updateWorkerStarted = true;
  } catch {
    updateWorkerStarted = true;
  }
  if (existsSync(join(home, ".gforge", "update.lock")) || existsSync(join(home, ".gforge", "update-log"))) {
    updateWorkerStarted = true;
  }

  const classified = classifyControls(clean, secret);
  if (updateWorkerStarted) {
    classified.result = "unexpected-status";
    classified.detail = `${classified.detail}; the update worker started during the probe`;
  }

  const outcome = {
    ...classified,
    platform: assessment.platform,
    warnings: assessment.warnings,
    worktree: "linked"
  };
  if (classified.result !== "protected") {
    const output = hookOutputOf(clean, secret);
    if (output) outcome.hookOutput = output;
  }
  return outcome;
}

export async function runProtectionProbe(options = {}) {
  const state = { root: null, child: null, disarm: () => {} };
  try {
    const assessment = await assessInstallation(options);
    if (!assessment.ok) {
      const report = formatProtectionProbeReport({
        result: "refused",
        reason: assessment.reason,
        detail: assessment.detail,
        platform: assessment.platform,
        warnings: assessment.warnings,
        commit: "not run"
      });
      return { exitCode: 1, result: "refused", reason: assessment.reason, report, disposableRoot: null };
    }

    state.root = await (options.createTempRoot ?? createTempRoot)(options.tmpdir);
    state.disarm = armProbeCleanup(state);
    const outcome = await executeProbe(state, assessment, options);
    const report = formatProtectionProbeReport(outcome);
    return {
      exitCode: outcome.result === "protected" ? 0 : 1,
      result: outcome.result,
      report,
      disposableRoot: state.root
    };
  } catch (error) {
    const report = formatProtectionProbeReport({
      result: state.root ? "setup-failed" : "refused",
      reason: state.root ? undefined : "probe-error",
      detail: redactProbeText(error?.message ?? String(error)),
      commit: "not run"
    });
    return {
      exitCode: 1,
      result: state.root ? "setup-failed" : "refused",
      reason: state.root ? undefined : "probe-error",
      report,
      disposableRoot: state.root
    };
  } finally {
    state.disarm?.();
    state.disarm = () => {};
    const child = state.child;
    if (child && child.exitCode === null && child.signalCode == null) {
      try {
        child.kill("SIGKILL");
      } catch {
        // already exited
      }
      await new Promise((resolve) => {
        child.once("close", resolve);
        setTimeout(resolve, 1000);
      });
    }
    if (state.root) {
      await removeProbeDirectory(state.root).catch(() => {});
    }
  }
}
