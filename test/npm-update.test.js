import assert from "node:assert/strict";
import test from "node:test";

import { readFile } from "node:fs/promises";
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

test("issue #78: the npm calls in npm-update.js run from the home directory", async () => {
  // On Windows these run through cmd.exe (npm is npm.cmd), and cmd.exe resolves
  // an unqualified command against the CURRENT DIRECTORY before PATH. Inheriting
  // the repository's cwd therefore let a repo-provided npm.cmd - untracked is
  // enough - run instead of the real npm. `gforge install`/`update` are run by
  // the developer from inside the repo, so this is not a corner case.
  const home = homedir();
  const seen = [];
  const record = (cmd, args, opts) => seen.push({ cmd, args: args.join(" "), cwd: opts?.cwd });

  await getLatestVersion({
    execFile: async (cmd, args, opts) => {
      record(cmd, args, opts);
      return { stdout: "1.2.3\n" };
    }
  });

  await performSelfUpgrade("update", "1.2.3", {
    skipReexec: true,
    execFile: async (cmd, args, opts) => {
      record(cmd, args, opts);
      return { stdout: "/usr/lib/node_modules\n" };
    },
    spawnSync: (cmd, args, opts) => {
      record(cmd, args, opts);
      return { status: 0 };
    }
  });

  // The exact set, not a minimum count: a floor of "at least three" passes even
  // when one of them loses its cwd, and says nothing about a call site added
  // later.
  assert.deepEqual(
    seen.filter((call) => call.cmd === "npm").map((call) => `${call.args} @ ${call.cwd}`),
    [
      `view gforge version @ ${home}`,
      `install -g gforge@latest @ ${home}`,
      `root -g @ ${home}`
    ]
  );

  // The re-exec of the freshly installed binary is also a spawn, but it runs
  // node against an absolute script path, so there is no unqualified name for
  // cmd.exe to resolve against the current directory - and it should keep
  // running where the developer invoked the command.
  const reexec = seen.find((call) => call.cmd !== "npm");
  assert.equal(reexec.cwd, undefined);
});

test("issue #78: every npm call site in src/ passes a cwd, including the background worker", async () => {
  // The worker in scanner.js is the call issue #78 actually names, and it is
  // unreachable from a unit test: it is not exported, and it spawns npm for
  // real. Without this the suite stayed green when its cwd was removed.
  //
  // So the invariant is asserted against the source itself, which also covers
  // `npm config get registry` and any call site added later - the previous test
  // could only ever see the three it drives by hand.
  // Named rather than derived from the URL, so the label in a failure message
  // needs no string surgery to produce.
  const sources = [
    { label: "src/npm-update.js", url: new URL("../src/npm-update.js", import.meta.url) },
    { label: "src/scanner.js", url: new URL("../src/scanner.js", import.meta.url) }
  ];
  const callSites = [];

  for (const { label, url } of sources) {
    const lines = (await readFile(url, "utf8")).split("\n");

    lines.forEach((line, index) => {
      if (!line.includes('("npm", [')) return;
      // The options object runs from this line to the line that closes the
      // call, which is the first `});` at or after it.
      const end = lines.findIndex((l, i) => i >= index && /^\s*}\s*\)/.test(l));
      const call = lines.slice(index, end === -1 ? index + 1 : end + 1).join("\n");
      callSites.push({
        where: `${label}:${index + 1}`,
        hasCwd: /\bcwd:\s*(?:homedir\(\)|npmCwd\(\))/.test(call)
      });
    });
  }

  // Guard the guard: if the shape of these calls ever changes so that none are
  // found, this test must not quietly pass while checking nothing.
  assert.ok(callSites.length >= 5, `expected to find the npm call sites, found ${callSites.length}`);
  assert.deepEqual(
    callSites.filter((site) => !site.hasCwd),
    [],
    "every npm invocation must pass cwd: homedir()"
  );
});

test("issue #78: a home directory that cannot be entered is reported, not swallowed", async () => {
  // Every npm call now depends on the cwd existing. spawnSync reports a failure
  // to start the child in `error` and leaves status null, so the old message
  // was "exited with status null", which tells the user nothing about why.
  const result = await performSelfUpgrade("update", "1.2.3", {
    spawnSync: () => ({ error: Object.assign(new Error("spawnSync npm ENOENT"), { code: "ENOENT" }), status: null })
  });

  assert.equal(result.ok, false);
  assert.match(result.error, /could not start \(ENOENT\)/);
  assert.match(result.error, new RegExp(homedir().replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.doesNotMatch(result.error, /status null/);
});
