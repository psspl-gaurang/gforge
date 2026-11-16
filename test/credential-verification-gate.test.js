import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

const srcDir = new URL("../src/", import.meta.url);
const read = (url) => readFileSync(url, "utf8");

// GH-127: live credential verification is not authorized. Any new outbound
// network call in src/ must be a deliberate, reviewed change to this test.
test("src/ makes no network calls beyond the update-check packument fetch", () => {
  const calls = [];
  for (const name of readdirSync(srcDir)) {
    if (!name.endsWith(".js")) continue;
    const lines = read(new URL(name, srcDir)).split("\n");
    lines.forEach((line, index) => {
      if (/^\s*\/\//.test(line)) return;
      if (/\bfetch\(|node:https?\b|node:net\b|node:tls\b|node:dgram\b/.test(line)) {
        calls.push(`${name}:${index + 1}: ${line.trim()}`);
      }
    });
  }
  assert.equal(calls.length, 1, `unexpected network code:\n${calls.join("\n")}`);
  assert.match(calls[0], /^scanner\.js:\d+: .*fetch\(packumentUrl\(registry\)/);
});

test("pre-commit blocking does not depend on verification state", () => {
  const scanner = read(new URL("scanner.js", srcDir));
  assert.doesNotMatch(scanner, /verif(?:y|ied|ication)[A-Za-z]*State|verified-(?:active|inactive)/);
});

test("PLAN.md records the GH-127 decision and its required sections", () => {
  const plan = read(new URL("../PLAN.md", import.meta.url));
  assert.match(plan, /## Credential Verification \(GH-127\): Decision Record/);
  for (const heading of [
    "Status",
    "Invariants (apply to any future design)",
    "Result states and benefit measurement",
    "Initial provider set (if ever approved)",
    "Network policy",
    "Opt-in",
    "Output redaction",
    "Side effects assessed",
    "Threat model",
    "Maintenance cost",
    "Tests required before implementation"
  ]) {
    assert.ok(plan.includes(`### ${heading}\n`), `missing section: ${heading}`);
  }
  for (const state of ["detected", "verified-active", "verified-inactive", "unverified", "unknown"]) {
    assert.ok(plan.includes(`\`${state}\``), `missing result state: ${state}`);
  }
  assert.match(plan, /no-go for implementation now/);
});
