import assert from "node:assert/strict";
import test from "node:test";

import { createVerificationReport, formatVerificationReport } from "../src/verify.js";

test("creates successful report when required checks pass", () => {
  const report = createVerificationReport(
    {
      platform: { name: "linux", arch: "x64", supported: true },
      home: { path: "/home/example", present: true },
      shell: { path: "/bin/bash", name: "bash", supported: true },
      node: { version: "20.11.0", major: 20, supported: true },
      git: { available: true, rawVersion: "git version 2.45.0" }
    },
    {
      checks: [{ status: "PASS", label: "hooks-path", detail: "configured" }]
    }
  );

  assert.equal(report.exitCode, 0);
  assert.equal(report.checks.every((check) => check.status === "PASS"), true);
});

test("reports the .env cross-reference so a silently dead layer is visible", () => {
  const monorepo = createVerificationReport(healthyEnvironment(), null, {
    inRepo: true,
    root: "/repo",
    files: ["client/.env", "server/.env"],
    secretCount: 7
  });
  const output = formatVerificationReport(monorepo);

  assert.equal(monorepo.exitCode, 0);
  assert.match(output, /PASS dotenv-cross-reference: 7 value\(s\) cross-referenced from client\/\.env, server\/\.env/);

  // No .env anywhere: the layer loads nothing, and verification must say so.
  const inactive = createVerificationReport(healthyEnvironment(), null, {
    inRepo: true,
    root: "/repo",
    files: [],
    secretCount: 0
  });
  assert.equal(inactive.exitCode, 0); // informational: a repo may legitimately have none
  assert.match(formatVerificationReport(inactive), /WARN dotenv-cross-reference: no \.env file found/);

  // Files found, but nothing secret-shaped in them: still inert.
  const empty = createVerificationReport(healthyEnvironment(), null, {
    inRepo: true,
    root: "/repo",
    files: [".env"],
    secretCount: 0
  });
  assert.match(formatVerificationReport(empty), /WARN dotenv-cross-reference: \.env hold no secret-shaped values/);

  // Outside a git repository the check is omitted entirely.
  const outside = createVerificationReport(healthyEnvironment(), null, {
    inRepo: false,
    root: null,
    files: [],
    secretCount: 0
  });
  assert.equal(outside.checks.some((check) => check.label === "dotenv-cross-reference"), false);
  assert.equal(createVerificationReport(healthyEnvironment()).checks.some((c) => c.label === "dotenv-cross-reference"), false);
});

test("formats warnings without failing verification", () => {
  const report = createVerificationReport({
    platform: { name: "linux", arch: "x64", supported: true },
    home: { path: "/home/example", present: true },
    shell: { path: null, name: null, supported: false },
    node: { version: "20.11.0", major: 20, supported: true },
    git: { available: true, rawVersion: "git version 2.45.0" }
  });

  assert.equal(report.exitCode, 0);
  assert.match(formatVerificationReport(report), /WARN shell: not detected/);
});

test("issue #42: a blocking check fails the exit code even though its status is WARN", () => {
  // The reported gap: `gforge verify && deploy` passed in a repository whose
  // own core.hooksPath shadows the managed hooks - the WARN's own text says
  // GForge will not run there, so a CI gate was treating a completely
  // unprotected repository as verified/healthy.
  const report = createVerificationReport(healthyEnvironment(), {
    checks: [
      { status: "PASS", label: "hooks-path", detail: "core.hooksPath is /home/example/.gforge/hooks" },
      {
        blocking: true,
        status: "WARN",
        label: "effective-hooks-path",
        detail: "core.hooksPath resolves to /repo/.husky/_ here; ... GForge will not run in this repository"
      }
    ]
  });

  assert.equal(report.exitCode, 1);
  // The reason is stated, so a non-zero exit is not inexplicable when every
  // printed line reads PASS or WARN.
  const output = formatVerificationReport(report);
  assert.match(output, /Not protected: effective-hooks-path/);
  assert.match(output, /scanning is not active/);
});

test("issue #42: informational WARNs still pass, so CI does not break on a missing .env", () => {
  // The fix keys off an explicit `blocking` flag rather than "any WARN".
  // Failing on every WARN would fail verification for repositories that simply
  // have no .env file, or whose shell is unrecognised - neither is a
  // protection gap, and both are common.
  const noEnvFile = createVerificationReport(healthyEnvironment(), null, {
    inRepo: true,
    root: "/repo",
    files: [],
    secretCount: 0
  });
  assert.equal(noEnvFile.checks.some((check) => check.status === "WARN"), true);
  assert.equal(noEnvFile.exitCode, 0);

  const noSecrets = createVerificationReport(healthyEnvironment(), null, {
    inRepo: true,
    root: "/repo",
    files: [".env"],
    secretCount: 0
  });
  assert.equal(noSecrets.exitCode, 0);

  // A classic hand-written hook going dormant means the user's OWN hook will
  // not run - GForge itself is active, so this must not fail verification.
  const classicDormant = createVerificationReport(healthyEnvironment(), {
    checks: [
      { status: "PASS", label: "hooks-path", detail: "configured" },
      { status: "WARN", label: "classic-hook-shadowed", detail: "/r/.git/hooks/pre-commit is executable but dormant" }
    ]
  });
  assert.equal(classicDormant.exitCode, 0);
  // No "Not protected" banner when nothing is actually blocking.
  assert.equal(/Not protected/.test(formatVerificationReport(classicDormant)), false);
});

test("issue #42: a FAIL still fails, and combines with blocking checks", () => {
  const report = createVerificationReport({
    platform: { name: "linux", arch: "x64", supported: true },
    home: { path: "/home/example", present: true },
    shell: { path: "/bin/bash", name: "bash", supported: true },
    node: { version: "20.11.0", major: 20, supported: true },
    git: { available: false, rawVersion: null }
  });

  assert.equal(report.exitCode, 1);
  assert.deepEqual(report.blocking, []);
});

test("issue #52: verify reports the Node version, and fails on one below the minimum", () => {
  const healthy = createVerificationReport(healthyEnvironment());
  const nodePass = healthy.checks.find((check) => check.label === "node");
  assert.ok(nodePass, "expected a node check");
  assert.equal(nodePass.status, "PASS");
  assert.match(formatVerificationReport(healthy), /PASS node: Node\.js 20\.11\.0/);

  const old = createVerificationReport({
    ...healthyEnvironment(),
    node: { version: "18.20.4", major: 18, supported: false }
  });
  const nodeFail = old.checks.find((check) => check.label === "node");
  assert.equal(nodeFail.status, "FAIL");
  assert.match(nodeFail.detail, /18\.20\.4/);
  assert.match(nodeFail.detail, /Upgrade Node/);
  assert.equal(old.exitCode, 1);

  // A FAIL, not a blocking check: an old runtime is untested, but it does not
  // prove that scanning is inactive the way a shadowed hooksPath does - so the
  // "Not protected" banner must not appear.
  assert.deepEqual(old.blocking, []);
  assert.equal(/Not protected/.test(formatVerificationReport(old)), false);
});

test("issue #52: a missing node field is reported rather than silently passing", () => {
  // Defensive: an environment object assembled without node detection must not
  // quietly count as healthy.
  const { node, ...withoutNode } = healthyEnvironment();
  const report = createVerificationReport(withoutNode);

  const check = report.checks.find((c) => c.label === "node");
  assert.equal(check.status, "FAIL");
  assert.equal(report.exitCode, 1);
});

function healthyEnvironment() {
  return {
    platform: { name: "linux", arch: "x64", supported: true },
    home: { path: "/home/example", present: true },
    shell: { path: "/bin/bash", name: "bash", supported: true },
    node: { version: "20.11.0", major: 20, supported: true },
    git: { available: true, rawVersion: "git version 2.45.0" }
  };
}

test("issue #130: approved secret sources are reported by path and count, and only when configured", () => {
  const source = (file, extra = {}) => ({ file, format: "json", keys: 1, count: 1, missing: 0, skipped: 0, incomplete: null, ...extra });
  const healthy = createVerificationReport(healthyEnvironment(), null, null, {
    configured: true,
    inRepo: true,
    sources: [source("api/config/local.json"), source("web/local.properties", { format: "properties" })],
    errors: [],
    secretCount: 2
  });
  assert.equal(healthy.exitCode, 0);
  assert.match(
    formatVerificationReport(healthy),
    /PASS approved-secret-sources: 2 value\(s\) cross-referenced from api\/config\/local\.json, web\/local\.properties/
  );

  const incomplete = createVerificationReport(healthyEnvironment(), null, null, {
    configured: true,
    inRepo: true,
    sources: [source("local.json"), source("gone.json", { count: 0, incomplete: "not found" })],
    errors: ["repository 1 source 3: file must not contain .. segments"],
    secretCount: 1
  });
  // Informational: the other layers still run, so this never fails verify.
  assert.equal(incomplete.exitCode, 0);
  assert.deepEqual(incomplete.blocking, []);
  assert.match(
    formatVerificationReport(incomplete),
    /WARN approved-secret-sources: 1 value\(s\) cross-referenced from local\.json, gone\.json; incomplete: gone\.json \(not found\), 1 problem\(s\) in ~\/\.gforge\/sources\.json/
  );

  const invalidOnly = createVerificationReport(healthyEnvironment(), null, null, {
    configured: true, inRepo: true, sources: [], errors: ["not valid JSON"], secretCount: 0
  });
  assert.match(formatVerificationReport(invalidOnly), /WARN approved-secret-sources: 0 value\(s\) cross-referenced from no approved source/);

  // Opt-in: nothing configured, nothing approved here, or outside a repo.
  for (const report of [
    { configured: false, inRepo: true, sources: [], errors: [], secretCount: 0 },
    { configured: true, inRepo: true, sources: [], errors: [], secretCount: 0 },
    { configured: true, inRepo: false, sources: [], errors: ["x"], secretCount: 0 },
    null
  ]) {
    const checks = createVerificationReport(healthyEnvironment(), null, null, report).checks;
    assert.equal(checks.some((c) => c.label === "approved-secret-sources"), false);
  }
});
