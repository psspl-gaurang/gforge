import assert from "node:assert/strict";
import test from "node:test";

import { homedir } from "node:os";

import { compareVersions, getLatestVersion, isNewer, performSelfUpgrade } from "../src/npm-update.js";

test("compareVersions orders semver numerically", () => {
  assert.equal(compareVersions("0.3.0", "0.2.4"), 1);
  assert.equal(compareVersions("0.2.4", "0.3.0"), -1);
  assert.equal(compareVersions("1.0.0", "0.9.9"), 1);
  assert.equal(compareVersions("0.2.10", "0.2.9"), 1); // numeric, not lexical
  assert.equal(compareVersions("0.2.4", "0.2.4"), 0);
});

test("isNewer is true only for strictly greater versions", () => {
  assert.equal(isNewer("0.3.0", "0.2.4"), true);
  assert.equal(isNewer("0.2.4", "0.2.4"), false);
  assert.equal(isNewer("0.2.3", "0.2.4"), false);
});

test("performSelfUpgrade installs the constant gforge@latest, never an interpolated version", async () => {
  const calls = [];
  const result = await performSelfUpgrade("update", "9.9.9", {
    spawnSync: (cmd, args) => {
      calls.push({ cmd, args });
      return { status: 0 };
    },
    // npm root -g returns nothing -> no re-exec, just the install step
    execFile: async () => ({ stdout: "" })
  });

  assert.equal(result.ok, true);
  const install = calls.find((c) => c.args && c.args[0] === "install");
  assert.deepEqual(install.args, ["install", "-g", "gforge@latest"]);
  // The registry-derived version must never appear in any spawned command.
  assert.equal(JSON.stringify(calls).includes("9.9.9"), false);
});

test("performSelfUpgrade passes a bounded timeout to the install step and fails clearly if it fires", async () => {
  const calls = [];
  const result = await performSelfUpgrade("update", "9.9.9", {
    spawnSync: (cmd, args, spawnOptions) => {
      calls.push({ cmd, args, spawnOptions });
      // Simulate spawnSync's own behavior when its timeout elapses: the
      // process is killed, status is null, and `error.code` is ETIMEDOUT.
      return { status: null, signal: "SIGTERM", error: Object.assign(new Error("timed out"), { code: "ETIMEDOUT" }) };
    }
  });

  assert.equal(result.ok, false);
  assert.match(result.error, /timed out after \d+ms/);
  const install = calls.find((c) => c.args && c.args[0] === "install");
  assert.equal(typeof install.spawnOptions.timeout, "number");
  assert.ok(install.spawnOptions.timeout > 0);
});

test("performSelfUpgrade refuses a version that is not plain semver (no command injection)", async () => {
  let spawned = false;
  const result = await performSelfUpgrade("update", "1.0.0 && rm -rf /", {
    spawnSync: () => {
      spawned = true;
      return { status: 0 };
    }
  });

  assert.equal(result.ok, false);
  assert.equal(spawned, false);
});

test("issue #78: every npm call runs from the home directory, not the caller's cwd", async () => {
  // On Windows these run through cmd.exe (npm is npm.cmd), and cmd.exe resolves
  // an unqualified command against the CURRENT DIRECTORY before PATH. Inheriting
  // the repository's cwd therefore let a repo-provided npm.cmd - untracked is
  // enough - run instead of the real npm. `gforge install`/`update` are run by
  // the developer from inside the repo, so this is not a corner case.
  const home = homedir();
  const seen = [];

  await getLatestVersion({
    execFile: async (cmd, args, opts) => {
      seen.push({ cmd, args: args.join(" "), cwd: opts?.cwd });
      return { stdout: "1.2.3\n" };
    }
  });

  await performSelfUpgrade("update", "1.2.3", {
    skipReexec: true,
    execFile: async (cmd, args, opts) => {
      seen.push({ cmd, args: args.join(" "), cwd: opts?.cwd });
      return { stdout: "/usr/lib/node_modules\n" };
    },
    spawnSync: (cmd, args, opts) => {
      seen.push({ cmd, args: args.join(" "), cwd: opts?.cwd });
      return { status: 0 };
    }
  });

  // Only the npm invocations: the re-exec of the freshly installed binary is
  // also a spawn, but it runs node against an absolute script path, so there is
  // no unqualified name for cmd.exe to resolve against the current directory -
  // and it should keep running where the developer invoked the command.
  const npmCalls = seen.filter((call) => call.cmd === "npm");
  assert.ok(npmCalls.length >= 3, `expected the npm calls to be covered, saw ${npmCalls.length}`);
  for (const call of npmCalls) {
    assert.equal(call.cwd, home, `npm ${call.args} must run from the home directory`);
  }
  // The install itself is the highest-value one to get right.
  assert.ok(npmCalls.some((c) => c.args.startsWith("install -g")), "expected the install call to be covered");
});
