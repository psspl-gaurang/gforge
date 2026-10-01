import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { runCli } from "../src/cli.js";
import { HISTORY_MAX_BLOB_BYTES, formatHistoryReport, scanHistory } from "../src/history.js";

// ---------------------------------------------------------------------------
// `gforge history` against real repositories (issue #88). Every git call here
// runs with the developer's own configuration shut out - GIT_CONFIG_GLOBAL at
// an empty file, no system config - and every commit with --no-verify: these
// fixtures commit secret-shaped values on purpose, and a real GForge hook on
// the machine would rightly refuse them.
//
// The values are assembled at runtime rather than written out, so this file
// does not itself contain anything the commit hook or GitHub's push
// protection would flag.
// ---------------------------------------------------------------------------
const assign = (key, value) => [key, value].join("=");
const LEAK_OLD = assign("DB_PASS", ["psspl@443e", "history"].join("-"));
const LEAK_LIVE = assign("API_TOKEN", ["s3cr3tToken", "StillHere", "123"].join("-"));
const LEAK_BRANCH = assign("SERVICE_PASSWORD", ["unmerged", "Secret", "998877"].join("-"));
const VALUES = [LEAK_OLD, LEAK_LIVE, LEAK_BRANCH].map((line) => line.split("=")[1]);

const roots = [];
test.after(async () => {
  await Promise.all(roots.map((dir) => rm(dir, { recursive: true, force: true })));
});

// realpath: on macOS the temp directory sits behind a /var -> /private/var
// symlink, and git reports the resolved toplevel.
async function tempDir(prefix) {
  const dir = await realpath(await mkdtemp(join(tmpdir(), prefix)));
  roots.push(dir);
  return dir;
}

async function makeRepo() {
  const root = await tempDir("gforge-history-");
  const repo = join(root, "repo");
  const home = join(root, "home"); // no ~/.gforge/rules.json here: no custom rules leak in
  await mkdir(repo);
  await mkdir(home);
  const env = {
    ...process.env,
    GIT_CONFIG_GLOBAL: join(root, "gitconfig"),
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_AUTHOR_NAME: "t",
    GIT_AUTHOR_EMAIL: "t@example.com",
    GIT_COMMITTER_NAME: "t",
    GIT_COMMITTER_EMAIL: "t@example.com"
  };
  await writeFile(env.GIT_CONFIG_GLOBAL, "");

  const git = (args, extraEnv = {}) => {
    const result = spawnSync("git", args, { cwd: repo, env: { ...env, ...extraEnv }, encoding: "utf8" });
    assert.equal(result.status, 0, `git ${args.join(" ")}: ${result.stderr}`);
    return result.stdout.trim();
  };
  git(["init", "-q", "-b", "main", "."]);

  const r = {
    root,
    repo,
    home,
    git,
    async write(path, content) {
      await mkdir(join(repo, path, ".."), { recursive: true });
      await writeFile(join(repo, path), content);
    },
    commit(message, extraEnv) {
      git(["add", "-A"]);
      git(["commit", "-q", "--no-verify", "--allow-empty", "-m", message], extraEnv);
      return git(["rev-parse", "HEAD"]);
    },
    scan(options = {}) {
      return scanHistory({ cwd: repo, home, dotenvSecrets: [], ...options });
    }
  };
  return r;
}

const ids = (result) => result.findings.map((f) => `${f.file}:${f.line} ${f.ruleId}`);

// ---------------------------------------------------------------------------
// What the scan finds, and where it says it came from.
// ---------------------------------------------------------------------------
test("issue #88: a secret committed and later deleted is still found, at the commit that leaked it", async () => {
  // The whole point: the commit hook never sees this - it was committed before
  // GForge was installed, and it is not in the tree any more.
  const r = await makeRepo();
  await r.write("app.js", "export const x = 1;\n");
  r.commit("init");
  await r.write("old config.txt", `${LEAK_OLD}\n`); // a space in the path, on purpose
  const leaked = r.commit("add config");
  r.git(["rm", "-q", "old config.txt"]);
  r.commit("remove config");

  const result = r.scan();
  assert.equal(result.ok, true);
  assert.deepEqual(ids(result), ["old config.txt:1 generic-secret-assignment"]);
  assert.equal(result.findings[0].commit.sha, leaked, "attributed to the commit that introduced it");
  assert.equal(result.findings[0].inHead, false, "not in the current tree any more");
  assert.equal(result.commitCount, 3);
});

test("issue #88: a secret still in the current tree is marked as such", async () => {
  // "Remove it now" and "it is already out there" are different jobs.
  const r = await makeRepo();
  await r.write("live.txt", `${LEAK_LIVE}\n`);
  await r.write("app.js", "export const x = 1;\n");
  r.commit("init");

  const result = r.scan();
  const live = result.findings.filter((f) => f.file === "live.txt");
  assert.ok(live.length > 0);
  assert.ok(live.every((f) => f.inHead));
  assert.equal(result.findings.some((f) => f.file === "app.js"), false, "a clean file is not flagged");
});

test("issue #88: a committed .env is found by name, even after it was removed", async () => {
  const r = await makeRepo();
  await r.write(".env", "PLACEHOLDER=1\n");
  r.commit("oops");
  r.git(["rm", "-q", ".env"]);
  r.commit("remove .env");

  assert.ok(ids(r.scan()).includes(".env:0 secret-file-env"));
});

test("issue #88: HEAD by default, every ref with --all", async () => {
  // Like `git log`: what the current branch can reach, unless asked for more.
  const r = await makeRepo();
  await r.write("app.js", "export const x = 1;\n");
  r.commit("init");
  r.git(["checkout", "-q", "-b", "feature"]);
  await r.write("feature.py", `${LEAK_BRANCH}\n`);
  r.commit("feature");
  r.git(["checkout", "-q", "main"]);

  assert.deepEqual(ids(r.scan()), []);
  const all = r.scan({ all: true });
  assert.ok(ids(all).includes("feature.py:1 generic-secret-assignment"));
  assert.equal(all.scope, "all refs");
});

test("issue #88: content that first appears in a merge resolution is not missed", async () => {
  // An "evil merge": the leak exists in neither parent. A log walk without -m
  // never looks inside merges and would report this history as clean.
  const r = await makeRepo();
  await r.write("app.js", "export const x = 1;\n");
  r.commit("init");
  r.git(["checkout", "-q", "-b", "side"]);
  await r.write("side.txt", "side\n");
  r.commit("side");
  r.git(["checkout", "-q", "main"]);
  await r.write("main.txt", "main\n");
  r.commit("main");
  r.git(["merge", "-q", "--no-ff", "--no-commit", "side"]);
  await r.write("resolved.txt", `${LEAK_OLD}\n`);
  const merge = r.commit("merge side");

  const finding = r.scan().findings.find((f) => f.file === "resolved.txt");
  assert.ok(finding, "the merge-only leak must be found");
  assert.equal(finding.commit.sha, merge);
});

test("issue #88: attribution follows ancestry, not commit timestamps", async () => {
  // git's default walk is date-ordered. Along a straight line that still
  // matches ancestry - a parent is only queued once its child is - so the case
  // needs a fork point: A has two children, and one of them carries a skewed
  // clock. The commit that leaked cfg.txt is A; P deletes it and Q, dated
  // years earlier, puts it back. Walked by date, Q surfaces before A and would
  // be credited with the leak.
  const r = await makeRepo();
  const at = (iso) => ({ GIT_AUTHOR_DATE: iso, GIT_COMMITTER_DATE: iso });
  await r.write("cfg.txt", `${LEAK_OLD}\n`);
  const first = r.commit("A: leak", at("2020-01-01T00:00:00Z"));
  r.git(["checkout", "-q", "-b", "side"]);
  await r.write("s.txt", "s\n");
  r.commit("S1", at("2025-01-01T00:00:00Z"));
  r.git(["checkout", "-q", "main"]);
  r.git(["rm", "-q", "cfg.txt"]);
  r.commit("P: remove", at("2030-01-01T00:00:00Z"));
  await r.write("cfg.txt", `${LEAK_OLD}\n`);
  r.commit("Q: re-add", at("2001-01-01T00:00:00Z"));
  r.git(["merge", "-q", "--no-ff", "side", "-m", "M"], at("2032-01-01T00:00:00Z"));

  const findings = r.scan().findings.filter((f) => f.file === "cfg.txt");
  assert.equal(findings.length, 1, "the same version at the same path is one finding");
  assert.equal(findings[0].commit.sha, first, "credited to A, the commit that leaked it");
});

test("issue #88: an unchanged file is scanned once, however many commits carry it", async () => {
  const r = await makeRepo();
  await r.write("constant.txt", "never changes\n");
  for (let i = 0; i < 5; i += 1) {
    await r.write("counter.txt", `${i}\n`);
    r.commit(`commit ${i}`);
  }

  const result = r.scan();
  assert.equal(result.commitCount, 5);
  // 1 version of constant.txt + 5 of counter.txt - not 10.
  assert.equal(result.scannedCount, 6);
});

test("issue #88: paths are parsed exactly, whatever bytes they contain", async () => {
  // git's -z output frames commits with \x01, and a path may legally contain
  // that byte - or a newline. Split on the framing byte, and a crafted path
  // desynchronises the parse and its content goes unscanned.
  const r = await makeRepo();
  const crafted = "we\x01ird\nname ünïcode.txt";
  await r.write(crafted, `${LEAK_OLD}\n`);
  await r.write("after.txt", `${LEAK_LIVE}\n`);
  r.commit("crafted");

  const files = new Set(r.scan().findings.map((f) => f.file));
  assert.ok(files.has(crafted), "the crafted path itself is reported intact");
  assert.ok(files.has("after.txt"), "and the file after it is not lost");
});

test("issue #88: a symlink's target is scanned, as the commit hook scans it", async () => {
  const r = await makeRepo();
  await symlink(LEAK_OLD, join(r.repo, "link"));
  r.commit("link");
  assert.ok(ids(r.scan()).includes("link:1 generic-secret-assignment"));
});

test("issue #88: user git config cannot change what the walk sees", async () => {
  // log.showRoot=false hides the root commit's files from `git log --raw`;
  // log.showSignature mixes GPG output into stdout. Both are neutralised.
  const r = await makeRepo();
  r.git(["config", "log.showRoot", "false"]);
  r.git(["config", "log.showSignature", "true"]);
  await r.write("root.txt", `${LEAK_OLD}\n`);
  r.commit("root commit");

  assert.ok(ids(r.scan()).includes("root.txt:1 generic-secret-assignment"));
});

// ---------------------------------------------------------------------------
// Suppressions: honoured by default, visible, and switchable off.
// ---------------------------------------------------------------------------
test("issue #88: the allowlist applies, is counted, and --no-allowlist overrides it", async () => {
  // A history audit must not be blindable by the repository under audit, so
  // what the allowlist hid is reported - and can be scanned anyway.
  const r = await makeRepo();
  await r.write(".gforgeignore", "^fixtures/\n");
  await r.write("fixtures/sample.txt", `${LEAK_OLD}\n`);
  await r.write("inline.txt", `${LEAK_LIVE} # gforge:allow\n`);
  r.commit("init");

  const honoured = r.scan();
  assert.deepEqual(ids(honoured), []);
  assert.equal(honoured.allowlistedCount, 1);
  assert.match(formatHistoryReport(honoured), /1 file version skipped by \.gforgeignore\/\.gitleaksignore - rerun with --no-allowlist/);

  const audit = r.scan({ allowlist: false });
  assert.ok(ids(audit).includes("fixtures/sample.txt:1 generic-secret-assignment"));
  assert.ok(ids(audit).includes("inline.txt:1 generic-secret-assignment"), "inline markers are ignored too");
  assert.equal(audit.allowlistedCount, 0);
});

// ---------------------------------------------------------------------------
// Everything not scanned is said out loud.
// ---------------------------------------------------------------------------
test("issue #88: a version over the size cap is named, not silently skipped", async () => {
  const r = await makeRepo();
  await r.write("dump.sql", Buffer.alloc(HISTORY_MAX_BLOB_BYTES + 1, 0x41));
  await r.write("app.js", "export const x = 1;\n");
  r.commit("big");

  const result = r.scan();
  assert.equal(result.oversized.length, 1);
  assert.equal(result.oversized[0].path, "dump.sql");
  assert.equal(result.scannedCount, 1);
  assert.match(formatHistoryReport(result), /1 file version over 10 MB not scanned: dump\.sql @ [0-9a-f]{12} \(10\.0 MB\)/);
});

test("issue #88: a partial clone reports what it lacks, and downloads nothing", async () => {
  // Reading a missing blob in a partial clone silently fetches it from the
  // remote - for a history scan, potentially all of history.
  const origin = await makeRepo();
  origin.git(["config", "uploadpack.allowFilter", "true"]);
  await origin.write("cfg.txt", "v1\n");
  origin.commit("one");
  await origin.write("cfg.txt", `${LEAK_OLD}\n`);
  origin.commit("two");
  await origin.write("cfg.txt", "v3\n");
  origin.commit("three");

  const clone = join(origin.root, "clone");
  const cloned = spawnSync("git", ["clone", "-q", "--filter=blob:none", `file://${origin.repo}`, clone], {
    env: { ...process.env, GIT_CONFIG_GLOBAL: join(origin.root, "gitconfig"), GIT_CONFIG_NOSYSTEM: "1" },
    encoding: "utf8"
  });
  assert.equal(cloned.status, 0, cloned.stderr);

  const result = scanHistory({ cwd: clone, home: origin.home, dotenvSecrets: [] });
  assert.equal(result.ok, true);
  assert.equal(result.unavailableCount, 2, "the two historical versions were never downloaded");
  assert.match(formatHistoryReport(result), /2 file versions not available locally \(a partial clone\)/);

  // And reading them did not fetch them.
  const blob = spawnSync("git", ["rev-parse", "HEAD~1:cfg.txt"], { cwd: clone, encoding: "utf8" }).stdout.trim();
  const present = spawnSync("git", ["cat-file", "-e", blob], {
    cwd: clone,
    env: { ...process.env, GIT_NO_LAZY_FETCH: "1" }
  });
  assert.notEqual(present.status, 0, "the scan must not have downloaded the blob");
});

test("issue #88: a shallow clone is flagged as incomplete", async () => {
  const origin = await makeRepo();
  await origin.write("a.txt", "1\n");
  origin.commit("one");
  await origin.write("a.txt", "2\n");
  origin.commit("two");

  const clone = join(origin.root, "shallow");
  const cloned = spawnSync("git", ["clone", "-q", "--depth", "1", `file://${origin.repo}`, clone], {
    env: { ...process.env, GIT_CONFIG_GLOBAL: join(origin.root, "gitconfig"), GIT_CONFIG_NOSYSTEM: "1" },
    encoding: "utf8"
  });
  assert.equal(cloned.status, 0, cloned.stderr);

  const result = scanHistory({ cwd: clone, home: origin.home, dotenvSecrets: [] });
  assert.equal(result.shallow, true);
  assert.match(formatHistoryReport(result), /shallow clone, so history older than its depth was not scanned/);
});

// ---------------------------------------------------------------------------
// Edges, and the CLI.
// ---------------------------------------------------------------------------
test("issue #88: outside a repository, and in one with no commits", async () => {
  const outside = await tempDir("gforge-history-norepo-");
  const none = scanHistory({ cwd: outside });
  assert.equal(none.ok, false);
  assert.match(formatHistoryReport(none), /not inside a git repository/);

  const r = await makeRepo();
  const empty = r.scan();
  assert.equal(empty.empty, true);
  assert.match(formatHistoryReport(empty), /no commits yet/);
  // --all on a repository with no refs is simply clean.
  assert.equal(r.scan({ all: true }).commitCount, 0);
});

test("issue #88: the report never prints a value, and tells you to rotate", async () => {
  const r = await makeRepo();
  await r.write("a.txt", `${LEAK_OLD}\n`);
  r.commit("one");
  await r.write("b.txt", `${LEAK_LIVE}\n`);
  r.commit("two");

  const report = formatHistoryReport(r.scan());
  for (const value of VALUES) assert.equal(report.includes(value), false, "a matched value must never be printed");
  assert.match(report, /potential secrets in 2 commits/);
  assert.match(report, /No secret values are printed above/);
  assert.match(report, /rotate it first/);
});

test("issue #88: `gforge history` exits 1 on findings and 0 when clean, so it can gate CI", async () => {
  const streams = () => {
    const out = { stdout: "", stderr: "" };
    return {
      out,
      io: { stdout: { write: (s) => (out.stdout += s) }, stderr: { write: (s) => (out.stderr += s) } }
    };
  };

  const clean = await makeRepo();
  await clean.write("app.js", "export const x = 1;\n");
  clean.commit("init");
  const ok = streams();
  assert.equal((await runCli(["history"], ok.io, { cwd: clean.repo, home: clean.home })).exitCode, 0);
  assert.match(ok.out.stdout, /no secrets found/);

  const dirty = await makeRepo();
  await dirty.write("a.txt", `${LEAK_OLD}\n`);
  dirty.commit("leak");
  const found = streams();
  assert.equal((await runCli(["history"], found.io, { cwd: dirty.repo, home: dirty.home })).exitCode, 1);
  assert.match(found.out.stdout, /a\.txt:1/);

  const bad = streams();
  assert.equal((await runCli(["history", "--bogus"], bad.io, { cwd: clean.repo })).exitCode, 1);
  assert.match(bad.out.stderr, /unknown option for history: --bogus/);

  const outside = streams();
  assert.equal((await runCli(["history"], outside.io, { cwd: await tempDir("gforge-history-cli-") })).exitCode, 1);
  assert.match(outside.out.stderr, /not inside a git repository/);
});
