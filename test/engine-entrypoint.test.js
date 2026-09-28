import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { getScannerContent } from "../src/hooks.js";
import { VERSION } from "../src/metadata.js";

// ---------------------------------------------------------------------------
// The engine as the hook actually runs it: the file getScannerContent() writes
// into ~/.gforge/hooks, executed by node, from inside a repository (issue #49).
//
// Nothing short of that reaches this code. Run from src/, RUNNING_VERSION is
// still the "__GFORGE_VERSION__" placeholder, and every update notice is
// deliberately skipped for an unbaked engine - so an in-process test would
// pass while exercising none of it.
//
// SAFETY. The commit path spawns a detached worker that runs `npm install -g`
// when its cache is stale. Every run here therefore puts a fake `npm` FIRST on
// PATH and points HOME at a throwaway directory, so no test can reach the real
// npm, the real registry, or the developer's own ~/.gforge. The fake records
// what it was asked to do, which is also how the tests observe the installer.
// ---------------------------------------------------------------------------
const FAKE_NPM = `#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const args = process.argv.slice(2);
if (args[0] === "config" && args[1] === "get" && args[2] === "registry") {
  process.stdout.write((process.env.FAKE_NPM_REGISTRY || "") + "\\n");
  process.exit(0);
}
fs.appendFileSync(process.env.FAKE_NPM_LOG, JSON.stringify({
  args,
  cwd: process.cwd(),
  registry: process.env.npm_config_registry ?? null
}) + "\\n");
// Emulates postinstall refreshing the managed engine, which is what a real
// global install does when GForge is active.
if (args[0] === "install" && process.env.FAKE_NPM_REFRESH === "1") {
  const version = /gforge@(\\d+\\.\\d+\\.\\d+)/.exec(args.join(" "))[1];
  const engine = path.join(process.env.HOME, ".gforge", "hooks", "gforge-scan.mjs");
  const source = fs.readFileSync(engine, "utf8");
  fs.writeFileSync(engine, source.replace(/const RUNNING_VERSION = "[^"]+"/, 'const RUNNING_VERSION = "' + version + '"'));
}
process.exit(Number(process.env.FAKE_NPM_EXIT || 0));
`;

const [MAJOR, MINOR, PATCH] = VERSION.split(".").map(Number);
const NEXT_PATCH = `${MAJOR}.${MINOR}.${PATCH + 1}`;
const NEXT_MINOR = `${MAJOR}.${MINOR + 1}.0`;
const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

// A throwaway machine: a home with the baked engine installed, a repository to
// commit in, and a bin directory holding only the fake npm.
async function machine(t) {
  // Resolved to its real path on purpose. On macOS the temp directory lives
  // under /var, a symlink to /private/var, and the engine's "was I run
  // directly?" guard compares process.argv[1] (the path as given, symlink
  // intact) with import.meta.url (which Node resolves to the real path). Through
  // any symlinked directory the two differ, the guard reads false, and the
  // engine exits 0 having scanned nothing. That is a real defect, not a test
  // artefact - a HOME with a symlink in its path makes every commit pass
  // unscanned while `gforge verify` reports a healthy install - and it is being
  // reported separately rather than fixed inside a test-only change.
  const root = await realpath(await mkdtemp(join(tmpdir(), "gforge-engine-")));
  t.after(() => rm(root, { recursive: true, force: true }));

  const home = join(root, "home");
  const hooks = join(home, ".gforge", "hooks");
  const repo = join(root, "repo");
  const bin = join(root, "bin");
  await mkdir(hooks, { recursive: true });
  await mkdir(repo);
  await mkdir(bin);

  await writeFile(join(hooks, "gforge-scan.mjs"), getScannerContent());
  // CommonJS, whatever package.json sits above the temp directory.
  await writeFile(join(bin, "package.json"), '{ "type": "commonjs" }\n');
  await writeFile(join(bin, "npm"), FAKE_NPM);
  await chmod(join(bin, "npm"), 0o755);

  const m = {
    root,
    home,
    repo,
    engine: join(hooks, "gforge-scan.mjs"),
    cache: join(home, ".gforge", "update-check.json"),
    log: join(home, ".gforge", "update-log"),
    lock: join(home, ".gforge", "update.lock"),
    npmLog: join(root, "npm-calls.jsonl"),
    env: {
      PATH: `${bin}:${process.env.PATH}`,
      HOME: home,
      USERPROFILE: home,
      TMPDIR: process.env.TMPDIR ?? tmpdir(),
      // The developer's own git config (a real core.hooksPath included) must
      // play no part.
      GIT_CONFIG_GLOBAL: join(root, "gitconfig"),
      GIT_CONFIG_NOSYSTEM: "1",
      NO_COLOR: "1",
      FAKE_NPM_LOG: join(root, "npm-calls.jsonl"),
      // Unreachable unless a test serves a registry, so a stray worker fails
      // fast rather than going anywhere real.
      FAKE_NPM_REGISTRY: "http://127.0.0.1:9/"
    }
  };

  const git = (...args) => {
    const result = spawnSync("git", args, { cwd: repo, env: m.env, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
  };
  git("init", "-q", ".");
  m.stage = async (name, content) => {
    await writeFile(join(repo, name), content);
    git("add", name);
  };
  return m;
}

// Async on purpose: a spawnSync would block this process's event loop, and the
// local registry the worker fetches from is served from this same process.
function runEngine(m, args, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [m.engine, ...args], { cwd: m.repo, env: { ...m.env, ...extraEnv } });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

// Written fresh so the commit path does not spawn a background worker.
function writeFreshCache(m, fields) {
  return writeFile(m.cache, `${JSON.stringify({ checkedAt: Date.now(), ...fields })}\n`);
}

async function npmCalls(m) {
  if (!existsSync(m.npmLog)) return [];
  return (await readFile(m.npmLog, "utf8")).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

// A registry serving one packument, recording what was asked of it.
async function serveRegistry(t, { versions }) {
  const requests = [];
  const packument = {
    name: "gforge",
    "dist-tags": { latest: Object.keys(versions).at(-1) },
    versions: Object.fromEntries(Object.keys(versions).map((v) => [v, { version: v }])),
    time: versions
  };
  const server = createServer((request, response) => {
    requests.push(request.url);
    if (request.url === "/gforge") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(packument));
    } else {
      response.writeHead(404).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return { url: `http://127.0.0.1:${server.address().port}/`, requests };
}

const ago = (ms) => new Date(Date.now() - ms).toISOString();

// Every regex metacharacter, not only ".": a prerelease version such as
// 1.0.0-beta+build carries a "+", which would otherwise act as an operator.
const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

async function waitFor(check, { timeoutMs = 20000, what }) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.fail(`timed out after ${timeoutMs}ms waiting for ${what}`);
}

const posixOnly = process.platform === "win32" ? "the fake npm is a POSIX executable" : false;

// ---------------------------------------------------------------------------
// The pre-commit entrypoint.
// ---------------------------------------------------------------------------
test("issue #49: the engine lets a clean commit through", { skip: posixOnly }, async (t) => {
  const m = await machine(t);
  await writeFreshCache(m, { latest: VERSION, versions: [VERSION], distTags: { latest: VERSION } });
  await m.stage("app.js", "export const greeting = 'hello';\n");

  const run = await runEngine(m, ["pre-commit"]);
  assert.equal(run.status, 0, run.stderr);
  assert.doesNotMatch(run.stderr, /COMMIT BLOCKED/);
});

test("issue #49: the engine blocks a staged secret without printing it", { skip: posixOnly }, async (t) => {
  const m = await machine(t);
  await writeFreshCache(m, { latest: VERSION, versions: [VERSION], distTags: { latest: VERSION } });
  // Not named `secret`: this file is itself scanned when committed, and a
  // credential keyword assigned a literal is exactly what the rule flags.
  const leakedValue = "psspl@443e-not-a-real-password";
  await m.stage("config.txt", `DB_PASS=${leakedValue}\n`);

  const run = await runEngine(m, ["pre-commit"]);
  assert.equal(run.status, 1);
  assert.match(run.stderr, /COMMIT BLOCKED/);
  assert.match(run.stderr, /config\.txt/);
  assert.match(run.stderr, /generic-secret-assignment/);
  assert.equal(run.stderr.includes(leakedValue), false, "the report must never contain the value");
});

// ---------------------------------------------------------------------------
// What the commit path says about updates. Only reachable from a baked engine.
// ---------------------------------------------------------------------------
test("issue #49: an unattended install is announced exactly once", { skip: posixOnly }, async (t) => {
  // A mandatory update channel that leaves no trace is not acceptable for a
  // security tool - but repeating it on every commit would be noise.
  const m = await machine(t);
  await writeFreshCache(m, {
    latest: VERSION,
    versions: [VERSION],
    distTags: { latest: VERSION },
    installed: { from: "0.0.1", to: VERSION, at: Date.now(), tier: "patch" }
  });
  await m.stage("app.js", "export {};\n");

  const first = await runEngine(m, ["pre-commit"]);
  assert.equal(first.status, 0, first.stderr);
  assert.match(first.stderr, new RegExp(`auto-updated v0\\.0\\.1 -> v${escapeRegExp(VERSION)}`));
  assert.equal(JSON.parse(await readFile(m.cache, "utf8")).installed.announced, true);

  const second = await runEngine(m, ["pre-commit"]);
  assert.equal(second.status, 0, second.stderr);
  assert.doesNotMatch(second.stderr, /auto-updated/);
});

test("issue #49: a package update that left the hook behind is said out loud", { skip: posixOnly }, async (t) => {
  // The engine running this very commit is the old one (issue #83).
  const m = await machine(t);
  await writeFreshCache(m, {
    latest: NEXT_PATCH,
    versions: [VERSION, NEXT_PATCH],
    distTags: { latest: NEXT_PATCH },
    hooksStale: { expected: NEXT_PATCH, onDisk: VERSION, at: Date.now() }
  });
  await m.stage("app.js", "export {};\n");

  const run = await runEngine(m, ["pre-commit"]);
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stderr, new RegExp(`updated to v${escapeRegExp(NEXT_PATCH)} but the managed hook is still v`));
  assert.match(run.stderr, /Run `gforge update`/);
});

test("issue #49: a pending same-major release is announced, and only when it is newer", { skip: posixOnly }, async (t) => {
  const m = await machine(t);
  await m.stage("app.js", "export {};\n");

  await writeFreshCache(m, { latest: NEXT_PATCH, versions: [VERSION, NEXT_PATCH], distTags: { latest: NEXT_PATCH } });
  const pending = await runEngine(m, ["pre-commit"]);
  assert.equal(pending.status, 0, pending.stderr);
  assert.match(pending.stderr, new RegExp(`v${escapeRegExp(NEXT_PATCH)} is available \\(you have v${escapeRegExp(VERSION)}\\)`));

  await writeFreshCache(m, { latest: VERSION, versions: [VERSION], distTags: { latest: VERSION } });
  const current = await runEngine(m, ["pre-commit"]);
  assert.equal(current.status, 0, current.stderr);
  assert.doesNotMatch(current.stderr, /is available/);
});

// ---------------------------------------------------------------------------
// The unattended installer: `gforge-scan.mjs __update-check`, the process the
// commit path spawns in the background.
// ---------------------------------------------------------------------------
test("issue #49: a matured patch is installed, pinned to the registry that vouched for it", { skip: posixOnly }, async (t) => {
  const m = await machine(t);
  const registry = await serveRegistry(t, { versions: { [VERSION]: ago(30 * DAY), [NEXT_PATCH]: ago(3 * DAY) } });

  const run = await runEngine(m, ["__update-check"], { FAKE_NPM_REGISTRY: registry.url });
  assert.equal(run.status, 0, run.stderr);

  // The metadata came from the configured registry...
  assert.deepEqual(registry.requests, ["/gforge"]);
  // ...and the install is the exact matured version, not `latest`, pinned to
  // that same registry through the environment (issue #79), run from the home
  // directory rather than the repository (issue #78).
  const installs = (await npmCalls(m)).filter((call) => call.args[0] === "install");
  assert.deepEqual(installs, [{ args: ["install", "-g", `gforge@${NEXT_PATCH}`], cwd: m.home, registry: registry.url }]);

  // The fake npm did not refresh the engine, so this must NOT be logged as a
  // success: the next commit would still run the old rules (issue #83).
  assert.match(await readFile(m.log, "utf8"), new RegExp(`installed-but-hooks-stale.* ${escapeRegExp(VERSION)} -> ${escapeRegExp(NEXT_PATCH)}`));
  assert.equal(JSON.parse(await readFile(m.cache, "utf8")).hooksStale.expected, NEXT_PATCH);
  assert.equal(existsSync(m.lock), false, "the worker must release its lock");
});

test("issue #49: a patch still inside its 48h quarantine is not installed", { skip: posixOnly }, async (t) => {
  const m = await machine(t);
  const registry = await serveRegistry(t, { versions: { [VERSION]: ago(30 * DAY), [NEXT_PATCH]: ago(1 * HOUR) } });

  const run = await runEngine(m, ["__update-check"], { FAKE_NPM_REGISTRY: registry.url });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual((await npmCalls(m)).filter((call) => call.args[0] === "install"), []);
  // The check still counts, so it waits a day rather than retrying every commit.
  const cache = JSON.parse(await readFile(m.cache, "utf8"));
  assert.ok(Date.now() - cache.checkedAt < 60000);
  assert.equal(cache.latest, NEXT_PATCH);
});

test("issue #49: GFORGE_AUTO_UPDATE=0 stops a minor from installing, but never a patch", { skip: posixOnly }, async (t) => {
  // The opt-out governs the minor and major tiers. Patch is where security
  // fixes ship, so it installs regardless - the issue asked for exactly this
  // opt-out check to be exercised against the real trigger.
  const versions = { [VERSION]: ago(30 * DAY), [NEXT_PATCH]: ago(3 * DAY), [NEXT_MINOR]: ago(10 * DAY) };

  const optedOut = await machine(t);
  const registryA = await serveRegistry(t, { versions });
  assert.equal((await runEngine(optedOut, ["__update-check"], { FAKE_NPM_REGISTRY: registryA.url, GFORGE_AUTO_UPDATE: "0" })).status, 0);
  assert.deepEqual(
    (await npmCalls(optedOut)).filter((c) => c.args[0] === "install").map((c) => c.args[2]),
    [`gforge@${NEXT_PATCH}`]
  );

  const defaults = await machine(t);
  const registryB = await serveRegistry(t, { versions });
  assert.equal((await runEngine(defaults, ["__update-check"], { FAKE_NPM_REGISTRY: registryB.url })).status, 0);
  assert.deepEqual(
    (await npmCalls(defaults)).filter((c) => c.args[0] === "install").map((c) => c.args[2]),
    [`gforge@${NEXT_MINOR}`]
  );
});

test("issue #49: an unreachable registry installs nothing and still stamps the check", { skip: posixOnly }, async (t) => {
  const m = await machine(t); // FAKE_NPM_REGISTRY stays on the discard port

  const run = await runEngine(m, ["__update-check"]);
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual((await npmCalls(m)).filter((call) => call.args[0] === "install"), []);
  const cache = JSON.parse(await readFile(m.cache, "utf8"));
  assert.ok(Date.now() - cache.checkedAt < 60000, "a failed check still waits a day before retrying");
  assert.equal(cache.latest, null);
});

// ---------------------------------------------------------------------------
// The whole chain, from an ordinary commit.
// ---------------------------------------------------------------------------
test("issue #49: an ordinary commit triggers the unattended install, and the next one announces it", { skip: posixOnly, timeout: 60000 }, async (t) => {
  const m = await machine(t);
  const registry = await serveRegistry(t, { versions: { [VERSION]: ago(30 * DAY), [NEXT_PATCH]: ago(3 * DAY) } });
  const env = { FAKE_NPM_REGISTRY: registry.url, FAKE_NPM_REFRESH: "1" };
  await m.stage("app.js", "export {};\n");

  // No cache: the commit itself is not delayed, but it spawns the detached
  // worker on its way out.
  const commit = await runEngine(m, ["pre-commit"], env);
  assert.equal(commit.status, 0, commit.stderr);

  await waitFor(async () => existsSync(m.log) && !existsSync(m.lock), { what: "the background worker to finish" });
  const installs = (await npmCalls(m)).filter((call) => call.args[0] === "install");
  assert.deepEqual(installs.map((c) => c.args[2]), [`gforge@${NEXT_PATCH}`]);
  // The fake refreshed the engine, so this time it is a real success.
  assert.match(await readFile(m.log, "utf8"), new RegExp(` installed patch ${escapeRegExp(VERSION)} -> ${escapeRegExp(NEXT_PATCH)}`));

  // The engine on disk is now the new version, and the next commit - run by
  // it - says what happened.
  const next = await runEngine(m, ["pre-commit"], env);
  assert.equal(next.status, 0, next.stderr);
  assert.match(next.stderr, new RegExp(`auto-updated v${escapeRegExp(VERSION)} -> v${escapeRegExp(NEXT_PATCH)}`));
});
