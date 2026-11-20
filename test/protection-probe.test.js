import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { describe, test } from "node:test";
import { promisify } from "node:util";

import {
  PRE_COMMIT_FILE_NAME,
  SCANNER_FILE_NAME,
  getManagedFiles,
  getScannerContent,
  resolveHooksDirectory,
  resolveStatePath
} from "../src/hooks.js";
import {
  PROBE_SYNTHETIC_SECRET,
  armProbeCleanup,
  classifyControls,
  formatProtectionProbeReport,
  removeProbeDirectory,
  runGitCommand,
  runProtectionProbe
} from "../src/protection-probe.js";

const execFileAsync = promisify(execFile);
const posixOnly = process.platform === "win32" ? "probe builds a POSIX PATH from symlinks" : false;

describe("protection probe", { concurrency: 1 }, () => {
  test("classifies allow, block, inert dispatch, and unexpected status", () => {
    const clean = run(0, "");
    const blocked = run(1, "GForge - COMMIT BLOCKED\nPotential secrets detected in staged changes:\n");

    assert.equal(classifyControls(clean, blocked).result, "protected");
    assert.match(classifyControls(clean, blocked).detail, /COMMIT BLOCKED/);
    assert.equal(classifyControls(clean, blocked).secret, "blocked (exit 1)");

    assert.equal(classifyControls(run(0, ""), run(0, "")).result, "inert-dispatch");
    assert.match(classifyControls(run(0, ""), run(0, "")).detail, /both commits were allowed/);

    assert.equal(classifyControls(run(1, "nope"), run(2, "nope")).result, "both-blocked");
    assert.match(classifyControls(run(1, "nope"), run(1, "nope")).detail, /clean file was not allowed/);

    const unexpected = classifyControls(run(0, ""), run(3, "hook status 3"));
    assert.equal(unexpected.result, "unexpected-status");
    assert.match(unexpected.detail, /clean exit 0; secret exit 3/);

    const missing = "GForge: no Node.js runtime found to scan for secrets; blocking commit for safety.";
    assert.equal(classifyControls(run(1, missing), run(1, missing)).result, "missing-runtime");

    const crashed = "GForge: secret scan could not complete, blocking commit for safety.";
    assert.equal(classifyControls(run(1, crashed), run(1, crashed)).result, "scan-incomplete");

    assert.equal(classifyControls(run(null, "", { signal: "SIGTERM" }), run(0, "")).result, "signal");
    assert.match(classifyControls(run(null, "", { signal: "SIGKILL" }), run(0, "")).detail, /SIGKILL/);
    assert.equal(classifyControls(run(null, ""), run(0, "")).result, "null-status");

    const leaked = classifyControls(
      run(0, ""),
      run(1, `COMMIT BLOCKED Potential secrets detected ${PROBE_SYNTHETIC_SECRET}`)
    );
    assert.equal(leaked.result, "unexpected-status");
    assert.equal(leaked.detail.includes(PROBE_SYNTHETIC_SECRET), false);
  });

  test("every report states the scope and scrubs the synthetic credential", () => {
    const report = formatProtectionProbeReport({
      result: "refused",
      reason: "hook-neutered",
      detail: `saw ${PROBE_SYNTHETIC_SECRET}`,
      commit: "not run"
    });
    assert.match(report, /result: refused/);
    assert.match(report, /reason: hook-neutered/);
    assert.match(report, /commit: not run/);
    assert.match(report, /one disposable repository, one clean file, one synthetic credential, the copied verified hook, and this process environment/);
    assert.match(report, /does not prove every repository or GUI environment is protected/);
    assert.match(report, /GUI client/);
    assert.match(report, /symlinked core\.hooksPath/);
    assert.match(report, /local or system hooks override/);
    assert.match(report, /custom rules/);
    assert.match(report, /gitleaks/);
    assert.match(report, /gitleaks layer was not exercised/);
    assert.match(report, /Custom rules were not loaded/);
    assert.equal(report.includes(PROBE_SYNTHETIC_SECRET), false);
    assert.match(report, /\[redacted\]/);
  });

  test("cleanup removes only the probe directory and drops its signal handlers", async (t) => {
    const parent = await realpath(await mkdtemp(join(tmpdir(), "gforge-ptest-")));
    t.after(() => rm(parent, { recursive: true, force: true }));
    const probeDir = await mkdtemp(join(parent, "gforge-probe-"));
    const sibling = await mkdtemp(join(parent, "gforge-probe-"));
    await writeFile(join(probeDir, "owned.txt"), "x");
    await writeFile(join(sibling, "keep.txt"), "y");

    const beforeInt = new Set(process.listeners("SIGINT"));
    const beforeTerm = new Set(process.listeners("SIGTERM"));
    const disarm = armProbeCleanup({ root: probeDir, child: null });
    const addedInt = process.listeners("SIGINT").filter((fn) => !beforeInt.has(fn));
    const addedTerm = process.listeners("SIGTERM").filter((fn) => !beforeTerm.has(fn));
    assert.equal(addedInt.length, 1);
    assert.equal(addedTerm.length, 1);
    disarm();
    assert.equal(process.listeners("SIGINT").includes(addedInt[0]), false);
    assert.equal(process.listeners("SIGTERM").includes(addedTerm[0]), false);

    await removeProbeDirectory(probeDir);
    assert.equal(existsSync(probeDir), false);
    assert.equal(await readFile(join(sibling, "keep.txt"), "utf8"), "y");
    const keeper = join(parent, "keep-me");
    await mkdir(keeper);
    await assert.rejects(() => removeProbeDirectory(parent), /refusing to remove/);
    await assert.rejects(() => removeProbeDirectory(keeper), /refusing to remove/);
    assert.equal(existsSync(sibling), true);
    assert.equal(existsSync(keeper), true);
    assert.equal(existsSync(parent), true);
  });

  test("refuses an unsupported platform before creating a repository", async (t) => {
    const { scratch } = await makeParent(t);
    const temp = forbidTemp();
    const result = await runProtectionProbe({
      environment: {
        ...environmentFor(join(scratch, "no-such-home")),
        platform: { name: "sunos", arch: "sparc", supported: false, isWsl: false }
      },
      createTempRoot: temp.createTempRoot,
      tmpdir: scratch
    });
    assert.equal(result.exitCode, 1);
    assert.equal(result.result, "refused");
    assert.equal(result.reason, "unsupported-platform");
    assert.equal(result.disposableRoot, null);
    assert.equal(temp.created, 0);
    assert.match(result.report, /platform: sunos sparc/);
    assert.match(result.report, /commit: not run/);
    assert.match(result.report, /does not prove every repository or GUI environment is protected/);
  });

  test("refuses a neutered shim and does not create a repository", async (t) => {
    const fixture = await makeParent(t);
    const home = join(fixture.root, "home");
    await mkdir(home, { recursive: true });
    await writeInstall(home, {
      preCommit: "#!/bin/sh\n# GForge managed pre-commit hook\nexit 0\n"
    });
    const temp = forbidTemp();
    const result = await runProtectionProbe(probeOptions(fixture, home, temp));
    assert.equal(result.result, "refused");
    assert.equal(result.reason, "hook-neutered");
    assert.match(result.report, /does not run the scanner/);
    assert.match(result.report, /commit: not run/);
    assert.equal(result.disposableRoot, null);
    assert.equal(temp.created, 0);
  });

  test("refuses a stale engine without executing it", async (t) => {
    const fixture = await makeParent(t);
    const home = join(fixture.root, "home");
    await mkdir(home, { recursive: true });
    await writeInstall(home, { scanner: `${getScannerContent()}\n// stale\n` });
    const temp = forbidTemp();
    const result = await runProtectionProbe(probeOptions(fixture, home, temp));
    assert.equal(result.reason, "engine-mismatch");
    assert.match(result.report, /stale or modified/);
    assert.equal(temp.created, 0);
    assert.match(result.report, /commit: not run/);
  });

  test("refuses an extra executable hook and does not run it", async (t) => {
    const fixture = await makeParent(t);
    const home = join(fixture.root, "home");
    await mkdir(home, { recursive: true });
    const hooks = await writeInstall(home);
    const marker = join(fixture.root, "extra-hook-ran");
    const extra = join(hooks, "commit-msg");
    await writeFile(extra, `#!/bin/sh\necho ran > ${JSON.stringify(marker)}\n`);
    await chmod(extra, 0o755);
    const temp = forbidTemp();
    const result = await runProtectionProbe(probeOptions(fixture, home, temp));
    assert.equal(result.reason, "extra-executable");
    assert.match(result.report, /commit-msg/);
    assert.match(result.report, /refusing to execute/);
    assert.equal(existsSync(marker), false);
    assert.equal(temp.created, 0);
  });

  test("a byte-identical hook allows a clean file, blocks a synthetic credential, and tears down", { skip: posixOnly }, async (t) => {
    const world = await installedWorld(t, { spaces: true });
    const seen = { commits: [], keys: [] };
    const result = await runProtectionProbe({
      ...world.options,
      lookupPath: `${world.fakeBin}${sep === "\\" ? ";" : ":"}${process.env.PATH}`,
      runGit: async (args, ctx) => {
        assertProbeEnv(ctx.env, world);
        if (args[0] === "commit") seen.commits.push({ cwd: ctx.cwd, message: args.at(-1) });
        if (args[0] === "config") {
          seen.keys.push(args[3]);
          if (args[3] === "commit.gpgsign" || args[3] === "tag.gpgsign") assert.equal(args[4], "false");
        }
        return runGitCommand(args, ctx);
      }
    });

    assert.equal(result.exitCode, 0, result.report);
    assert.equal(result.result, "protected");
    assert.match(result.report, new RegExp(`platform: ${process.platform}`));
    assert.match(result.report, /clean: allowed \(exit 0\)/);
    assert.match(result.report, /secret: blocked \(exit 1\)/);
    assert.match(result.report, /worktree: linked/);
    assert.match(result.report, /COMMIT BLOCKED/);
    assert.match(result.report, /gitleaks layer was not exercised/);
    assert.equal(result.report.includes("did not execute"), false);
    assert.equal(result.report.includes(PROBE_SYNTHETIC_SECRET), false);
    assert.deepEqual(seen.commits.map((commit) => commit.message), ["gforge probe clean", "gforge probe synthetic"]);
    for (const commit of seen.commits) {
      assert.ok(commit.cwd.endsWith(`${sep}linked-worktree`), commit.cwd);
      assert.ok(commit.cwd.includes(`${sep}probe tmp${sep}`), commit.cwd);
    }
    assert.deepEqual(seen.keys, ["user.name", "user.email", "core.hooksPath", "commit.gpgsign", "tag.gpgsign"]);
    assert.equal(existsSync(result.disposableRoot), false);
    assert.ok(result.disposableRoot.startsWith(world.probeParent));
    assert.equal(existsSync(world.marker), false);
    assert.equal(await readFile(world.gitconfig, "utf8"), world.gitconfigBefore);
    assert.deepEqual(await treeSnapshot(world.home), world.homeBefore);
  });

  test("a shadowed hooks path is reported and the other hook is not executed", { skip: posixOnly }, async (t) => {
    const world = await installedWorld(t, { spaces: false });
    const foreign = join(world.root, "foreign hooks");
    await mkdir(foreign, { recursive: true });
    const marker = join(world.root, "foreign-hook-ran");
    await writeFile(join(foreign, "pre-commit"), `#!/bin/sh\necho ran > ${JSON.stringify(marker)}\n`);
    await chmod(join(foreign, "pre-commit"), 0o755);
    await execFileAsync("git", ["init", "-q"], { cwd: world.gateCwd, env: world.gateEnv });
    await execFileAsync("git", ["config", "core.hooksPath", foreign], { cwd: world.gateCwd, env: world.gateEnv });
    const gitconfigBefore = await readFile(world.gitconfig, "utf8");
    const homeBefore = await treeSnapshot(world.home);

    const result = await runProtectionProbe(world.options);

    assert.equal(result.exitCode, 0, result.report);
    assert.equal(result.result, "protected");
    assert.match(result.report, /effective-hooks-path/);
    assert.ok(result.report.includes(foreign), result.report);
    assert.match(result.report, /did not execute any other hooks path/);
    assert.match(result.report, /does not prove every repository or GUI environment is protected/);
    assert.equal(existsSync(marker), false);
    assert.equal(result.report.includes(PROBE_SYNTHETIC_SECRET), false);
    assert.equal(existsSync(result.disposableRoot), false);
    assert.equal(await readFile(world.gitconfig, "utf8"), gitconfigBefore);
    assert.deepEqual(await treeSnapshot(world.home), homeBefore);
  });

  test("a missing Node runtime is visible and the temporary repository is removed", { skip: posixOnly }, async (t) => {
    const world = await installedWorld(t, { nodePath: "/no/such/gforge-probe-node" });
    const result = await runProtectionProbe(world.options);
    assert.equal(result.exitCode, 1);
    assert.equal(result.result, "missing-runtime");
    assert.match(result.report, /no Node\.js runtime found to scan for secrets/);
    assert.match(result.report, /clean: exit 1/);
    assert.match(result.report, /secret: exit 1/);
    assert.equal(result.report.includes(PROBE_SYNTHETIC_SECRET), false);
    assert.equal(existsSync(result.disposableRoot), false);
    assert.equal(await readFile(world.gitconfig, "utf8"), world.gitconfigBefore);
    assert.deepEqual(await treeSnapshot(world.home), world.homeBefore);
  });

  test("an unexpected hook status is visible and the temporary repository is removed", { skip: posixOnly }, async (t) => {
    const world = await installedWorld(t);
    const result = await runProtectionProbe({
      ...world.options,
      runGit: async (args, ctx) => {
        if (args[0] === "commit" && args.at(-1) === "gforge probe clean") {
          return { status: 0, signal: null, stdout: "", stderr: "" };
        }
        if (args[0] === "commit" && args.at(-1) === "gforge probe synthetic") {
          return { status: 3, signal: null, stdout: "", stderr: "hook status 3" };
        }
        return runGitCommand(args, ctx);
      }
    });
    assert.equal(result.exitCode, 1);
    assert.equal(result.result, "unexpected-status");
    assert.match(result.report, /clean exit 0; secret exit 3/);
    assert.match(result.report, /hook status 3/);
    assert.equal(result.report.includes(PROBE_SYNTHETIC_SECRET), false);
    assert.equal(existsSync(result.disposableRoot), false);
  });
});

function run(status, stderr, extra = {}) {
  return { status, signal: extra.signal ?? null, stdout: extra.stdout ?? "", stderr };
}

function environmentFor(home) {
  return {
    platform: { name: process.platform, arch: process.arch, supported: true, isWsl: false },
    home: { path: home, present: true },
    shell: { path: "/bin/bash", name: "bash", supported: true },
    node: {
      version: process.versions.node,
      major: Number(process.versions.node.split(".")[0]),
      supported: true
    },
    git: { available: true, version: "2.43.0", rawVersion: "git version 2.43.0" }
  };
}

function closedGit() {
  return async () => {
    const error = new Error("unset");
    error.code = 1;
    throw error;
  };
}

function forbidTemp() {
  const state = { created: 0 };
  return {
    get created() {
      return state.created;
    },
    async createTempRoot() {
      state.created += 1;
      throw new Error("temp root should not be created");
    }
  };
}

async function makeParent(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "gforge-ptest-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const scratch = join(root, "scratch");
  await mkdir(scratch, { recursive: true });
  return { root, scratch };
}

async function writeInstall(home, { nodePath = process.execPath, scanner, preCommit } = {}) {
  const hooks = resolveHooksDirectory(home);
  await mkdir(hooks, { recursive: true });
  const managed = getManagedFiles(nodePath);
  const scannerFile = managed.find((file) => file.name === SCANNER_FILE_NAME);
  const pre = managed.find((file) => file.name === PRE_COMMIT_FILE_NAME);
  await writeFile(join(hooks, SCANNER_FILE_NAME), scanner ?? scannerFile.content);
  await writeFile(join(hooks, PRE_COMMIT_FILE_NAME), preCommit ?? pre.content);
  await chmod(join(hooks, PRE_COMMIT_FILE_NAME), 0o755);
  await writeFile(
    resolveStatePath(home),
    `${JSON.stringify({
      version: 2,
      managedBy: "gforge",
      hooksDirectory: hooks,
      nodePath,
      previousCoreHooksPath: null
    }, null, 2)}\n`
  );
  return hooks;
}

function probeOptions(fixture, home, temp) {
  return {
    environment: environmentFor(home),
    execFile: closedGit(),
    createTempRoot: temp.createTempRoot,
    tmpdir: fixture.scratch
  };
}

async function treeSnapshot(dir) {
  const out = [];
  async function walk(current) {
    let entries = [];
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) await walk(full);
      else out.push([full.slice(dir.length), await readFile(full, "utf8")]);
    }
  }
  await walk(dir);
  out.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return out;
}

async function installedWorld(t, { spaces = false, nodePath = process.execPath } = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "gforge-ptest-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const home = join(root, spaces ? "User Home" : "home");
  const scratch = join(root, "scratch");
  const probeParent = await mkdirReal(join(root, "probe tmp"));
  const gateCwd = await mkdirReal(join(root, "gate cwd"));
  const xdg = join(root, "gate-xdg");
  await mkdir(home, { recursive: true });
  await mkdir(scratch, { recursive: true });
  await mkdir(join(xdg, "config"), { recursive: true });
  await mkdir(join(xdg, "data"), { recursive: true });
  await mkdir(join(xdg, "runtime"), { recursive: true });
  await writeInstall(home, { nodePath });

  const gitconfig = join(root, "user-gitconfig");
  const gateEnv = {
    HOME: home,
    USERPROFILE: home,
    PATH: process.env.PATH,
    GIT_CONFIG_GLOBAL: gitconfig,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
    TMPDIR: scratch,
    XDG_CONFIG_HOME: join(xdg, "config"),
    XDG_DATA_HOME: join(xdg, "data"),
    XDG_RUNTIME_DIR: join(xdg, "runtime"),
    XDG_CACHE_HOME: join(xdg, "cache")
  };
  await mkdir(gateEnv.XDG_CACHE_HOME, { recursive: true });
  await execFileAsync("git", ["config", "--file", gitconfig, "core.hooksPath", resolveHooksDirectory(home)], {
    cwd: gateCwd,
    env: gateEnv
  });

  const fakeBin = join(root, "fake-bin");
  const marker = join(root, "network-marker");
  await mkdir(fakeBin, { recursive: true });
  const fake = `#!/bin/sh\necho ran >> ${JSON.stringify(marker)}\n`;
  await writeFile(join(fakeBin, "npm"), fake);
  await writeFile(join(fakeBin, "gitleaks"), fake);
  await chmod(join(fakeBin, "npm"), 0o755);
  await chmod(join(fakeBin, "gitleaks"), 0o755);

  const options = {
    environment: environmentFor(home),
    execFile: (command, args) => execFileAsync(command, args, { cwd: gateCwd, env: gateEnv, encoding: "utf8" }),
    tmpdir: probeParent,
    lookupPath: `${fakeBin}:${process.env.PATH}`
  };

  return {
    root,
    home,
    probeParent,
    gateCwd,
    gateEnv,
    gitconfig,
    gitconfigBefore: await readFile(gitconfig, "utf8"),
    homeBefore: await treeSnapshot(home),
    fakeBin,
    marker,
    options
  };
}

async function mkdirReal(dir) {
  await mkdir(dir, { recursive: true });
  return realpath(dir);
}

const CHILD_ENV_KEYS = [
  "GIT_CONFIG_GLOBAL",
  "GIT_CONFIG_NOSYSTEM",
  "GIT_TERMINAL_PROMPT",
  "HOME",
  "LC_ALL",
  "NO_COLOR",
  "PATH",
  "TEMP",
  "TMP",
  "TMPDIR",
  "USERPROFILE",
  "XDG_CACHE_HOME",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "XDG_RUNTIME_DIR"
];

function assertProbeEnv(env, world) {
  assert.deepEqual(Object.keys(env).sort(), CHILD_ENV_KEYS);
  assert.equal(env.GIT_CONFIG_NOSYSTEM, "1");
  assert.equal(env.GIT_TERMINAL_PROMPT, "0");
  assert.equal(env.NO_COLOR, "1");
  assert.equal("GFORGE_NODE" in env, false);
  assert.equal("GIT_DIR" in env, false);
  assert.equal(env.PATH.includes(":"), false);
  assert.equal(env.PATH.includes(world.fakeBin), false);
  assert.ok(env.HOME.startsWith(world.probeParent), env.HOME);
  assert.notEqual(env.HOME, world.home);
  assert.ok(env.GIT_CONFIG_GLOBAL.startsWith(world.probeParent));
  assert.notEqual(env.GIT_CONFIG_GLOBAL, world.gitconfig);
  for (const key of ["TMPDIR", "TEMP", "TMP", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR", "XDG_CACHE_HOME"]) {
    assert.ok(env[key].startsWith(world.probeParent), `${key}=${env[key]}`);
  }
}
