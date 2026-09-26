import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { STAGED_DIFF_FILTER } from "../src/scanner.js";

// These run real git, because the bug was in what git was asked for rather than
// in any logic the rest of the suite can reach: every other scanner test passes
// `files` explicitly and so never exercises the staged-file listing at all.

const repos = [];
test.after(async () => {
  await Promise.all(repos.map((dir) => rm(dir, { recursive: true, force: true })));
});

test("issue #80: the staged-file filter includes type changes", () => {
  // D is excluded on purpose (a deletion stages no content), and U likewise
  // (git refuses to commit a conflicted path), but T stages full content.
  assert.match(STAGED_DIFF_FILTER, /T/);
  for (const status of ["A", "C", "M", "R"]) {
    assert.match(STAGED_DIFF_FILTER, new RegExp(status), `${status} must stay in the filter`);
  }
  assert.equal(STAGED_DIFF_FILTER.includes("D"), false);
});

test("issue #80: a symlink replaced by a real file is listed for scanning", { skip: process.platform === "win32" ? "symlinks need elevation on Windows" : false }, async () => {
  // The reported bypass: git reports this as T, so the old ACMR filter returned
  // nothing and the staged secret was never read by any rule.
  const repo = await makeRepo();
  await symlink("/etc/hosts", join(repo, "mylink"));
  git(repo, ["add", "mylink"]);
  git(repo, ["commit", "-m", "add symlink"]);

  await rm(join(repo, "mylink"));
  // In the real bypass this file holds a credential. The assertion here is
  // only about whether git lists the path at all, so the content is kept
  // deliberately non-credential-shaped - otherwise this repo would have to
  // allowlist its own test file against its own scanner.
  await writeFile(join(repo, "mylink"), "contents after the type change\n");
  git(repo, ["add", "mylink"]);

  // Precondition: git really does classify this as a type change.
  assert.match(git(repo, ["diff", "--cached", "--name-status"]), /^T\s+mylink/m);

  assert.deepEqual(listStaged(repo, STAGED_DIFF_FILTER), ["mylink"]);
  // And the filter this replaced genuinely missed it, so the test is not
  // passing for some unrelated reason.
  assert.deepEqual(listStaged(repo, "ACMR"), []);
});

test("issue #80: ordinary statuses are unaffected, and a deletion stays excluded", async () => {
  const repo = await makeRepo();
  await writeFile(join(repo, "kept.txt"), "one\n");
  await writeFile(join(repo, "gone.txt"), "two\n");
  git(repo, ["add", "."]);
  git(repo, ["commit", "-m", "init"]);

  await writeFile(join(repo, "kept.txt"), "changed\n");
  await writeFile(join(repo, "added.txt"), "new\n");
  await rm(join(repo, "gone.txt"));
  git(repo, ["add", "-A"]);

  const staged = listStaged(repo, STAGED_DIFF_FILTER).sort();
  assert.deepEqual(staged, ["added.txt", "kept.txt"]);
  // A deleted path has no staged content to scan, so it must not be listed.
  assert.equal(staged.includes("gone.txt"), false);
});

function git(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
}

function listStaged(cwd, filter) {
  const out = git(cwd, ["diff", "--cached", "-z", "--name-only", `--diff-filter=${filter}`]);
  return out.split("\0").filter(Boolean);
}

async function makeRepo() {
  const dir = await mkdtemp(join(tmpdir(), "gforge-staged-"));
  repos.push(dir);
  git(dir, ["init", "-q", "."]);
  git(dir, ["config", "user.email", "test@example.com"]);
  git(dir, ["config", "user.name", "test"]);
  git(dir, ["config", "commit.gpgsign", "false"]);
  return dir;
}
