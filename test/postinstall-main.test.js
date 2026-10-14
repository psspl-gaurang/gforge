import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

// ---------------------------------------------------------------------------
// main() itself: the orchestration the pure helpers in postinstall.test.js
// feed into. It runs unattended on `npm install -g`, so the only honest test is
// to run the real script, as npm would, against a git configuration isolated
// from the developer's own: GIT_CONFIG_GLOBAL / GIT_CONFIG_SYSTEM point git's
// global and system scopes at throwaway files, and HOME at a throwaway
// directory (issue #48).
//
// Deliberately a separate file that NEVER imports the script in-process. The
// script calls process.exit() when it believes it was run directly, so if that
// guard ever broke, a top-level import would exit the test process before a
// single test registered - and `node --test` reports that as one passing
// test. postinstall.test.js does import it, and would go silently green with
// all of its tests gone. This file cannot, so the guard test below is what
// turns the suite red instead.
// ---------------------------------------------------------------------------

const POSTINSTALL = fileURLToPath(new URL("../scripts/postinstall.js", import.meta.url));

async function isolatedMachine(t) {
  const root = await mkdtemp(join(tmpdir(), "gforge-postinstall-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const home = join(root, "home");
  await mkdir(home);
  return {
    root,
    home,
    hooksDirectory: join(home, ".gforge", "hooks"),
    globalConfig: join(root, "gitconfig-global"),
    systemConfig: join(root, "gitconfig-system")
  };
}

// Built from scratch rather than spread from process.env: an inherited CI=true
// (GitHub Actions sets it) would skip every run, and an inherited GIT_DIR or
// GIT_CONFIG_* would point git back at a real configuration.
function postinstallEnv(machine, overrides = {}) {
  const env = {
    PATH: process.env.PATH,
    HOME: machine.home,
    USERPROFILE: machine.home,
    GIT_CONFIG_GLOBAL: machine.globalConfig,
    GIT_CONFIG_SYSTEM: machine.systemConfig,
    npm_config_global: "true",
    ...overrides
  };
  for (const [key, value] of Object.entries(env)) if (value === undefined) delete env[key];
  return env;
}

function runPostinstall(machine, overrides) {
  return spawnSync(process.execPath, [POSTINSTALL], {
    cwd: machine.root, // not a git repository, so no repo-local config can interfere
    env: postinstallEnv(machine, overrides),
    encoding: "utf8",
    timeout: 30000
  });
}

function gitConfigValue(file) {
  const result = spawnSync("git", ["config", "--file", file, "--get", "core.hooksPath"], { encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : null;
}

function setGitConfig(file, value) {
  const result = spawnSync("git", ["config", "--file", file, "core.hooksPath", value], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
}

test("issue #48: a fresh global install sets up the hooks and says so", async (t) => {
  const machine = await isolatedMachine(t);

  const run = runPostinstall(machine);
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /installed global git hooks — every commit is now scanned for secrets/);
  assert.match(run.stdout, /gforge verify/);

  // It did what it said: global git config now points at the managed hooks,
  // and the hooks it points at exist.
  assert.equal(gitConfigValue(machine.globalConfig), machine.hooksDirectory);
  assert.equal(existsSync(join(machine.hooksDirectory, "pre-commit")), true);
  assert.equal(existsSync(join(machine.hooksDirectory, "gforge-scan.mjs")), true);
  // The system scope is read, never written.
  assert.equal(existsSync(machine.systemConfig), false);
});

test("issue #48: re-running over an active install refreshes rather than re-announcing", async (t) => {
  // `npm install -g gforge` again is how people upgrade. The message has to
  // say the hooks were refreshed, not claim a first-time setup.
  const machine = await isolatedMachine(t);
  assert.equal(runPostinstall(machine).status, 0);

  // Tamper with the engine so a refresh is observable, not just claimed.
  const engine = join(machine.hooksDirectory, "gforge-scan.mjs");
  await writeFile(engine, "// stale\n");

  const again = runPostinstall(machine);
  assert.equal(again.status, 0, again.stderr);
  assert.match(again.stdout, /refreshed the managed git hooks to the installed version/);
  assert.doesNotMatch(again.stdout, /installed global git hooks/);
  assert.notEqual(await readFile(engine, "utf8"), "// stale\n");
});

test("issue #48: an existing global hooksPath is reported and left exactly as it was", async (t) => {
  const machine = await isolatedMachine(t);
  setGitConfig(machine.globalConfig, "/opt/husky/hooks");

  const run = runPostinstall(machine);
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /a global core\.hooksPath is already set \(\/opt\/husky\/hooks\)/);
  assert.match(run.stdout, /Run `gforge install` if you want GForge to manage it/);

  // Not overwritten, and nothing half-installed alongside it.
  assert.equal(gitConfigValue(machine.globalConfig), "/opt/husky/hooks");
  assert.equal(existsSync(machine.hooksDirectory), false);
});

test("issue #48: a system-level hooksPath is respected even with nothing set globally", async (t) => {
  // Writing a global value here would outrank the system one in git's real
  // precedence and silently shadow an org policy (issue #41).
  const machine = await isolatedMachine(t);
  setGitConfig(machine.systemConfig, "/etc/org-hooks");

  const run = runPostinstall(machine);
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /a system-level core\.hooksPath is already set \(\/etc\/org-hooks\)/);
  assert.equal(gitConfigValue(machine.globalConfig), null);
  assert.equal(gitConfigValue(machine.systemConfig), "/etc/org-hooks");
  assert.equal(existsSync(machine.hooksDirectory), false);
});

test("issue #48: a local install, CI, or the skip variable leaves the machine untouched", async (t) => {
  const skipped = {
    "local install (no -g)": { npm_config_global: undefined },
    "CI": { CI: "true" },
    "GFORGE_SKIP_POSTINSTALL": { GFORGE_SKIP_POSTINSTALL: "1" }
  };

  for (const [name, overrides] of Object.entries(skipped)) {
    const machine = await isolatedMachine(t);
    const run = runPostinstall(machine, overrides);
    assert.equal(run.status, 0, `${name}: ${run.stderr}`);
    assert.equal(run.stdout, "", `${name}: must stay silent`);
    assert.equal(existsSync(machine.globalConfig), false, `${name}: must not write git config`);
    assert.equal(existsSync(join(machine.home, ".gforge")), false, `${name}: must not create ~/.gforge`);
  }
});

test("issue #48: a machine without git never fails the npm install", async (t) => {
  // The script's first rule: whatever goes wrong, `npm install` must succeed.
  // An empty PATH leaves node (spawned by absolute path) but no git at all.
  const machine = await isolatedMachine(t);
  const emptyBin = join(machine.root, "empty-bin");
  await mkdir(emptyBin);

  const run = runPostinstall(machine, { PATH: emptyBin });
  assert.equal(run.status, 0, run.stderr);
  // And it must not claim a success it did not achieve.
  assert.doesNotMatch(run.stdout, /installed global git hooks|refreshed the managed git hooks/);
  assert.equal(existsSync(machine.globalConfig), false);
});

test("issue #48: an install that throws still leaves npm install succeeding", {
  // chmod is not a barrier to root, and Windows permissions do not map onto it.
  skip: process.platform === "win32" || process.getuid?.() === 0 ? "needs a non-root POSIX user" : false
}, async (t) => {
  // The case the error handling exists for. An unwritable home makes
  // installManagedHooks throw EACCES rather than return ok:false - so unlike
  // the missing-git case above, this is main() genuinely rejecting.
  const machine = await isolatedMachine(t);
  await chmod(machine.home, 0o500);
  let run;
  try {
    run = runPostinstall(machine);
  } finally {
    // Restored here rather than in t.after: after-hooks run in registration
    // order, so the directory would already be gone by the time it ran.
    await chmod(machine.home, 0o700);
  }

  assert.equal(run.status, 0, run.stderr);
  assert.doesNotMatch(run.stdout, /installed global git hooks|refreshed the managed git hooks/);
  // Failed before touching git config, so nothing points at hooks that do not exist.
  assert.equal(existsSync(machine.globalConfig), false);
});

test("issue #48: importing the script does not run the install", async (t) => {
  // The guard that lets the tests above import the pure helpers. If it broke,
  // merely importing the module - with npm_config_global=true in the
  // environment - would rewrite the machine's global git config.
  const machine = await isolatedMachine(t);
  const probe = `await import(${JSON.stringify(pathToFileURL(POSTINSTALL).href)}); console.log("still running");`;

  const run = spawnSync(process.execPath, ["--input-type=module", "-e", probe], {
    cwd: machine.root,
    env: postinstallEnv(machine),
    encoding: "utf8",
    timeout: 30000
  });
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.stdout.trim(), "still running");
  assert.equal(existsSync(machine.globalConfig), false);
  assert.equal(existsSync(join(machine.home, ".gforge")), false);
});
