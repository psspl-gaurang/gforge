import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  KNOWN_SECRETS_MAX,
  SECRET_SOURCE_MAX_BYTES,
  SECRET_SOURCE_MAX_DEPTH,
  SECRET_SOURCES_TOTAL_MAX_BYTES,
  describeApprovedSecretSources,
  formatApprovedSourceWarnings,
  formatReport,
  jsonNestingDepth,
  loadApprovedSecretSources,
  looksLikeApprovedSecretValue,
  parseCustomRules,
  parseProperties,
  parseSecretSources,
  scanFileContent,
  scanStaged,
  secretSourcesPath
} from "../src/scanner.js";

// ---------------------------------------------------------------------------
// Approved local secret sources (issue #130). Every test builds its own home
// and repository under a fresh temp directory; nothing reads the developer's
// own ~/.gforge. Secret-shaped values are assembled at runtime so this file
// does not itself trip a commit hook.
// ---------------------------------------------------------------------------
const opts = { runGitleaks: false, allowlist: [], dotenvSecrets: [] };
const value = (...parts) => parts.join("-");
const DB_PASSWORD = value("Db9pass", "Vx72Kq", "live");
const API_TOKEN = value("tok", "8fG2mQ7wZ", "x41");
const OTHER_TOKEN = value("svc", "Pz3Lr8Ty", "990");

const tempDirs = [];
test.after(() => {
  for (const dir of tempDirs) {
    try {
      chmodSync(dir, 0o700);
    } catch {
      // already gone
    }
    rmSync(dir, { recursive: true, force: true });
  }
});

function makeTemp(prefix) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  tempDirs.push(dir);
  return dir;
}

function write(root, path, content) {
  const full = join(root, path);
  mkdirSync(join(full, ".."), { recursive: true });
  writeFileSync(full, content);
  return full;
}

// A home with ~/.gforge/sources.json approving `sources` for `repo`.
function setup(files = {}, sources = [], extraRepositories = []) {
  const base = makeTemp("gforge-sources-");
  const repo = join(base, "repo");
  const home = join(base, "home");
  mkdirSync(repo);
  mkdirSync(home);
  for (const [path, content] of Object.entries(files)) write(repo, path, content);
  writeConfig(home, { repositories: [{ path: repo, sources }, ...extraRepositories] });
  return { base, repo, home };
}

function writeConfig(home, config) {
  write(home, ".gforge/sources.json", typeof config === "string" ? config : JSON.stringify(config));
}

const json = (file, keys) => ({ file, format: "json", keys });
const allOutput = (report) => JSON.stringify(report) + formatApprovedSourceWarnings(report, "/home/dev");

test("issue #130: the schema accepts repositories with json and properties sources", () => {
  const { repositories, errors } = parseSecretSources(
    JSON.stringify({
      repositories: [
        {
          path: "/work/app",
          sources: [
            json("config\\secrets.local.json", ["db.password", "api.token"]),
            { file: "./app-local.properties", format: "PROPERTIES", keys: ["stripe.secret"] }
          ]
        }
      ]
    })
  );
  assert.deepEqual(errors, []);
  assert.deepEqual(repositories, [
    {
      path: "/work/app",
      sources: [
        { file: "config/secrets.local.json", format: "json", keys: ["db.password", "api.token"] },
        { file: "app-local.properties", format: "properties", keys: ["stripe.secret"] }
      ]
    }
  ]);
});

test("issue #130: invalid entries are rejected one by one and the rest survive", () => {
  const { repositories, errors } = parseSecretSources(
    JSON.stringify({
      repositories: [
        { path: "relative/repo", sources: [] },
        {
          path: "/work/app",
          sources: [
            json("/etc/passwd", ["x"]),
            json("C:\\Users\\me\\secrets.json", ["x"]),
            json("../outside.json", ["x"]),
            json("pkg/../../outside.json", ["x"]),
            json(".git/config", ["x"]),
            json("a\0b.json", ["x"]),
            { file: "config.yaml", format: "yaml", keys: ["x"] },
            { file: "config.toml", format: "toml", keys: ["x"] },
            { file: "config.ini", format: "ini", keys: ["x"] },
            json("nokeys.json", []),
            json("emptysegment.json", ["a..b"]),
            json("good.json", ["db.password"]),
            json("good.json", ["db.password"])
          ]
        },
        "not an object"
      ]
    })
  );

  assert.deepEqual(repositories, [
    { path: "/work/app", sources: [{ file: "good.json", format: "json", keys: ["db.password"] }] }
  ]);
  const text = errors.join("\n");
  assert.match(text, /repository 1: path must be an absolute path/);
  assert.equal((text.match(/must be relative to the repository/g) ?? []).length, 2);
  assert.equal((text.match(/must not contain \.\. segments/g) ?? []).length, 2);
  assert.match(text, /must not be inside \.git/);
  assert.match(text, /control characters/);
  assert.match(text, /format "yaml" is not supported yet/);
  assert.match(text, /format "toml" is not supported yet/);
  assert.match(text, /config\.ini: format must be json or properties/);
  assert.match(text, /nokeys\.json: keys must list/);
  assert.match(text, /no empty segments/);
  assert.match(text, /good\.json: listed more than once/);
  assert.match(text, /repository 3: not an object/);

  assert.deepEqual(parseSecretSources("{ nope"), { repositories: [], errors: ["not valid JSON"] });
  assert.match(parseSecretSources("[]").errors[0], /"repositories" array/);
  assert.deepEqual(parseSecretSources(""), { repositories: [], errors: [] });
});

test("issue #130: the schema enforces entry, key and path limits", () => {
  const many = (count, make) => Array.from({ length: count }, (_, i) => make(i));
  assert.match(
    parseSecretSources(JSON.stringify({ repositories: many(101, () => ({ path: "/r", sources: [] })) })).errors[0],
    /too many repositories/
  );
  assert.match(
    parseSecretSources(
      JSON.stringify({ repositories: [{ path: "/r", sources: many(51, (i) => json(`s${i}.json`, ["k"])) }] })
    ).errors[0],
    /too many sources/
  );
  const limited = (source) => parseSecretSources(JSON.stringify({ repositories: [{ path: "/r", sources: [source] }] }));
  assert.match(limited(json("k.json", many(101, (i) => `k${i}`))).errors[0], /too many keys/);
  assert.match(limited(json("k.json", ["k".repeat(201)])).errors[0], /at most 200 characters/);
  assert.match(limited(json("k.json", [many(33, () => "a").join(".")])).errors[0], /at most 32 segments/);
  assert.match(limited(json(`${"d/".repeat(200)}f.json`, ["k"])).errors[0], /at most 400 characters/);
});

test("issue #130: nothing is loaded unless sources.json exists in the home directory", () => {
  const base = makeTemp("gforge-sources-");
  const repo = join(base, "repo");
  const home = join(base, "home");
  mkdirSync(home);
  write(repo, "config/secrets.local.json", JSON.stringify({ db: { password: DB_PASSWORD } }));
  // A cloned repository shipping its own approvals - in any of the places a
  // home file would sit - must change nothing.
  const planted = JSON.stringify({ repositories: [{ path: repo, sources: [json("config/secrets.local.json", ["db.password"])] }] });
  write(repo, ".gforge/sources.json", planted);
  write(repo, "sources.json", planted);
  write(repo, ".gforgesources", planted);

  const loaded = loadApprovedSecretSources(repo, home);
  assert.equal(loaded.configured, false);
  assert.deepEqual(loaded.secrets, []);
  assert.deepEqual(loaded.sources, []);
  assert.equal(secretSourcesPath(home), join(home, ".gforge", "sources.json"));

  // Approvals for a different repository do not apply here either.
  writeConfig(home, { repositories: [{ path: join(base, "elsewhere"), sources: [json("config/secrets.local.json", ["db.password"])] }] });
  const other = loadApprovedSecretSources(repo, home);
  assert.equal(other.configured, true);
  assert.deepEqual(other.secrets, []);
  assert.deepEqual(other.sources, []);
});

test("issue #130: selected JSON and properties values are cross-referenced in staged files", () => {
  const { repo, home } = setup(
    {
      "config/secrets.local.json": JSON.stringify({ db: { password: DB_PASSWORD, host: "db.internal.example" } }),
      "app-local.properties": `# local only\napi.token = ${API_TOKEN}\n`
    },
    [json("config/secrets.local.json", ["db.password"]), { file: "app-local.properties", format: "properties", keys: ["api.token"] }]
  );

  const loaded = loadApprovedSecretSources(repo, home);
  assert.deepEqual(loaded.secrets.sort(), [API_TOKEN, DB_PASSWORD].sort());
  assert.deepEqual(loaded.errors, []);
  assert.deepEqual(
    loaded.sources.map(({ file, format, count, incomplete }) => ({ file, format, count, incomplete })),
    [
      { file: "config/secrets.local.json", format: "json", count: 1, incomplete: null },
      { file: "app-local.properties", format: "properties", count: 1, incomplete: null }
    ]
  );

  const leak = scanStaged({
    ...opts,
    knownSecrets: loaded.secrets,
    files: ["src/db.js"],
    read: () => `const pool = connect({ password: "${DB_PASSWORD}" });`
  });
  const finding = leak.findings.find((f) => f.ruleId === "hardcoded-known-secret");
  assert.ok(finding);
  assert.equal(finding.line, 1);
  assert.match(finding.description, /approved local secret source/);
  assert.doesNotMatch(formatReport(leak), new RegExp(DB_PASSWORD));

  // An unselected field (host) is never extracted.
  assert.equal(
    scanFileContent("src/db.js", 'const host = "db.internal.example";', { knownSecrets: loaded.secrets }).length,
    0
  );
});

test("issue #130: scanStaged loads approved sources from the given home", () => {
  const { repo, home } = setup(
    { "config/secrets.local.json": JSON.stringify({ api: { token: API_TOKEN } }) },
    [json("config/secrets.local.json", ["api.token"]), json("config/missing.json", ["api.token"])]
  );
  // The developer's own git config plays no part, here or in repoRoot().
  const saved = { GIT_CONFIG_GLOBAL: process.env.GIT_CONFIG_GLOBAL, GIT_CONFIG_NOSYSTEM: process.env.GIT_CONFIG_NOSYSTEM };
  process.env.GIT_CONFIG_GLOBAL = write(home, "gitconfig", "");
  process.env.GIT_CONFIG_NOSYSTEM = "1";
  const result = spawnSync("git", ["init", "-q", "."], { cwd: repo });
  assert.equal(result.status, 0);
  const cwd = process.cwd();
  process.chdir(repo);
  try {
    const scan = scanStaged({
      ...opts,
      home,
      files: ["src/client.js"],
      read: () => `fetch(url, { headers: { authorization: "${API_TOKEN}" } });`
    });
    assert.ok(scan.findings.some((f) => f.ruleId === "hardcoded-known-secret"));
    // The result carries source identity and counts, never the values.
    assert.equal("secrets" in scan.approvedSources, false);
    assert.doesNotMatch(JSON.stringify(scan.approvedSources), new RegExp(API_TOKEN));
    const warning = formatApprovedSourceWarnings(scan.approvedSources, home);
    assert.match(warning, /config\/missing\.json \(json\): not found/);
    assert.match(warning, /other scanner layers are unaffected/);
  } finally {
    process.chdir(cwd);
    for (const [key, previous] of Object.entries(saved)) {
      if (previous === undefined) delete process.env[key];
      else process.env[key] = previous;
    }
  }
});

test("issue #130: monorepo packages can each approve their own private files", () => {
  const { repo, home } = setup(
    {
      "services/api/config/local.json": JSON.stringify({ secrets: { db: DB_PASSWORD } }),
      "services/web/local.properties": `stripe.secret=${API_TOKEN}\n`,
      "packages/worker/config/local.json": JSON.stringify({ queue: { token: OTHER_TOKEN } })
    },
    [
      json("services/api/config/local.json", ["secrets.db"]),
      { file: "services/web/local.properties", format: "properties", keys: ["stripe.secret"] },
      json("packages/worker/config/local.json", ["queue.token"])
    ]
  );
  const loaded = loadApprovedSecretSources(repo, home);
  assert.equal(loaded.secrets.length, 3);
  for (const secret of [DB_PASSWORD, API_TOKEN, OTHER_TOKEN]) {
    const findings = scanFileContent("services/web/src/pay.js", `const key = "${secret}";`, {
      knownSecrets: loaded.secrets
    });
    assert.ok(findings.some((f) => f.ruleId === "hardcoded-known-secret"));
  }

  // A repository entry under its own subdirectory does not cover the root,
  // and the root's entry does not reach a sibling repository.
  const described = describeApprovedSecretSources(join(repo, "services"), home);
  assert.equal(described.secretCount, 0);
});

test("issue #130: duplicate sources and values are reported once", () => {
  const { repo, home } = setup({
    "a.json": JSON.stringify({ token: API_TOKEN }),
    "b.properties": `token=${API_TOKEN}\n`
  });
  // The same repository approved twice, under two spellings, repeating a file.
  writeConfig(home, {
    repositories: [
      {
        path: repo,
        sources: [json("a.json", ["token", "token"]), { file: "b.properties", format: "properties", keys: ["token"] }]
      },
      { path: `${repo}/`, sources: [json("./a.json", ["token"])] }
    ]
  });

  const loaded = loadApprovedSecretSources(repo, home);
  assert.deepEqual(loaded.secrets, [API_TOKEN]);
  assert.equal(loaded.sources.length, 2);
  assert.equal(loaded.sources[0].count, 1);
  assert.equal(loaded.sources[1].count, 0); // already counted from a.json
  assert.match(loaded.errors.join("\n"), /a\.json: approved more than once/);

  // A value shared with .env produces one finding, under the .env rule.
  const findings = scanFileContent("src/app.js", `const t = "${API_TOKEN}";`, {
    dotenvSecrets: [API_TOKEN],
    knownSecrets: loaded.secrets
  });
  assert.deepEqual(findings.map((f) => f.ruleId), ["hardcoded-dotenv-secret"]);
});

test("issue #130: weak, placeholder and reference values are not extracted", () => {
  const weak = {
    short: "abc123",
    word: "password",
    placeholder: "your_api_key_here",
    changeme: "changeme",
    digits: "12345678901234",
    repeated: "xxxxxxxxxxxx",
    masked: "************",
    template: "${DB_PASSWORD}",
    mustache: "{{ .Values.token }}",
    onePassword: "op://vault/item/password",
    vault: "vault://secret/data/app",
    arn: "arn:aws:secretsmanager:us-east-1:123456789012:secret:app",
    angle: "<your token>",
    number: 12345678901234,
    object: { nested: API_TOKEN },
    bool: true,
    real: DB_PASSWORD
  };
  const { repo, home } = setup({ "local.json": JSON.stringify(weak) }, [json("local.json", Object.keys(weak))]);
  const loaded = loadApprovedSecretSources(repo, home);
  assert.deepEqual(loaded.secrets, [DB_PASSWORD]);
  assert.equal(loaded.sources[0].skipped, Object.keys(weak).length - 1);
  assert.equal(loaded.sources[0].incomplete, null);

  assert.equal(looksLikeApprovedSecretValue(DB_PASSWORD), true);
  assert.equal(looksLikeApprovedSecretValue("development"), false);
});

test("issue #130: a cross-referenced value does not match inside a longer token", () => {
  const findings = scanFileContent("src/a.js", `const id = "x${API_TOKEN}y";`, { knownSecrets: [API_TOKEN] });
  assert.equal(findings.some((f) => f.ruleId === "hardcoded-known-secret"), false);
  const clean = scanFileContent("src/a.js", 'const label = "Password";', { knownSecrets: [API_TOKEN] });
  assert.deepEqual(clean, []);
});

test("issue #130: a changed value is picked up on the next load and the old one is dropped", () => {
  const { repo, home } = setup({ "local.json": JSON.stringify({ token: API_TOKEN }) }, [json("local.json", ["token"])]);
  assert.deepEqual(loadApprovedSecretSources(repo, home).secrets, [API_TOKEN]);
  write(repo, "local.json", JSON.stringify({ token: OTHER_TOKEN }));
  const after = loadApprovedSecretSources(repo, home);
  assert.deepEqual(after.secrets, [OTHER_TOKEN]);
  const oldLeak = scanFileContent("src/a.js", `t = "${API_TOKEN}"`, { knownSecrets: after.secrets });
  assert.equal(oldLeak.length > 0 && oldLeak.some((f) => f.ruleId === "hardcoded-known-secret"), false);
});

test("issue #130: malformed and missing input is reported as incomplete without leaking content", () => {
  const { repo, home } = setup(
    {
      "broken.json": `{ "token": "${API_TOKEN}", `,
      "partial.json": JSON.stringify({ token: API_TOKEN }),
      "binary.properties": `token=${API_TOKEN}\0\0\0`
    },
    [
      json("broken.json", ["token"]),
      json("partial.json", ["token", "absent.key"]),
      { file: "binary.properties", format: "properties", keys: ["token"] },
      json("missing.json", ["token"])
    ]
  );
  const loaded = loadApprovedSecretSources(repo, home);
  const reasons = Object.fromEntries(loaded.sources.map((s) => [s.file, s.incomplete]));
  assert.deepEqual(reasons, {
    "broken.json": "not valid JSON",
    "partial.json": "1 of 2 selected key(s) not found",
    "binary.properties": "not a text file",
    "missing.json": "not found"
  });
  assert.deepEqual(loaded.secrets, [API_TOKEN]); // partial.json still contributes
  assert.doesNotMatch(allOutput(describeApprovedSecretSources(repo, home)), new RegExp(API_TOKEN));

  // A malformed sources.json is reported, never thrown, and never echoed.
  writeConfig(home, `{ "repositories": [ "${API_TOKEN}"`);
  const bad = loadApprovedSecretSources(repo, home);
  assert.deepEqual(bad.errors, ["not valid JSON"]);
  assert.deepEqual(bad.secrets, []);
});

test("issue #130: reads cannot escape the repository through symlinks", { skip: process.platform === "win32" }, () => {
  const { base, repo, home } = setup({}, [
    json("outside-link.json", ["token"]),
    json("linked-dir/secrets.json", ["token"]),
    json("loop.json", ["token"]),
    json("inside-link.json", ["token"]),
    json("git-link.json", ["token"]),
    json("a-directory", ["token"])
  ]);
  write(base, "outside/secrets.json", JSON.stringify({ token: OTHER_TOKEN }));
  write(repo, "real/secrets.json", JSON.stringify({ token: API_TOKEN }));
  write(repo, ".git/secrets.json", JSON.stringify({ token: OTHER_TOKEN }));
  mkdirSync(join(repo, "a-directory"));
  symlinkSync(join(base, "outside/secrets.json"), join(repo, "outside-link.json"));
  symlinkSync(join(base, "outside"), join(repo, "linked-dir"));
  symlinkSync("loop.json", join(repo, "loop.json"));
  symlinkSync("real/secrets.json", join(repo, "inside-link.json"));
  symlinkSync(".git/secrets.json", join(repo, "git-link.json"));

  const loaded = loadApprovedSecretSources(repo, home);
  const reasons = Object.fromEntries(loaded.sources.map((s) => [s.file, s.incomplete]));
  assert.deepEqual(reasons, {
    "outside-link.json": "resolves outside the repository",
    "linked-dir/secrets.json": "resolves outside the repository",
    "loop.json": "symlink loop",
    "inside-link.json": null,
    "git-link.json": "resolves inside .git",
    "a-directory": "not a regular file"
  });
  // Only the link that stays inside the repository was read.
  assert.deepEqual(loaded.secrets, [API_TOKEN]);
});

test("issue #130: a permission failure is an incomplete source, not a crash", { skip: process.platform === "win32" || process.getuid?.() === 0 }, () => {
  const { repo, home } = setup({ "locked.json": JSON.stringify({ token: API_TOKEN }) }, [json("locked.json", ["token"])]);
  chmodSync(join(repo, "locked.json"), 0o000);
  try {
    const loaded = loadApprovedSecretSources(repo, home);
    assert.equal(loaded.sources[0].incomplete, "permission denied");
    assert.deepEqual(loaded.secrets, []);
  } finally {
    chmodSync(join(repo, "locked.json"), 0o600);
  }

  chmodSync(join(home, ".gforge", "sources.json"), 0o000);
  try {
    const loaded = loadApprovedSecretSources(repo, home);
    assert.deepEqual(loaded.errors, ["could not be read (permission denied)"]);
  } finally {
    chmodSync(join(home, ".gforge", "sources.json"), 0o600);
  }
});

test("issue #130: size, depth, read and value budgets are enforced", () => {
  const deep = `${"[".repeat(SECRET_SOURCE_MAX_DEPTH + 1)}${"]".repeat(SECRET_SOURCE_MAX_DEPTH + 1)}`;
  assert.equal(jsonNestingDepth(deep), SECRET_SOURCE_MAX_DEPTH + 1);
  assert.equal(jsonNestingDepth('{"a":"[[[[{{{{"}'), 1); // brackets inside strings do not count

  const big = JSON.stringify({ token: API_TOKEN, pad: "p".repeat(SECRET_SOURCE_MAX_BYTES) });
  const { repo, home } = setup({ "deep.json": deep, "big.json": big }, [json("deep.json", ["0"]), json("big.json", ["token"])]);
  const reasons = loadApprovedSecretSources(repo, home).sources.map((s) => s.incomplete);
  assert.deepEqual(reasons, [`nested deeper than ${SECRET_SOURCE_MAX_DEPTH} levels`, "larger than 1 MB"]);

  // Total bytes across one repository's sources.
  const nearLimit = JSON.stringify({ token: API_TOKEN, pad: "p".repeat(SECRET_SOURCE_MAX_BYTES - 100) });
  const count = Math.ceil(SECRET_SOURCES_TOTAL_MAX_BYTES / nearLimit.length) + 1;
  const files = Object.fromEntries(Array.from({ length: count }, (_, i) => [`f${i}.json`, nearLimit]));
  const budget = setup(files, Object.keys(files).map((file) => json(file, ["token"])));
  const budgetReasons = loadApprovedSecretSources(budget.repo, budget.home).sources.map((s) => s.incomplete);
  assert.equal(budgetReasons.at(-1), "read budget exhausted");
  assert.equal(budgetReasons[0], null);

  // Total distinct values.
  const keys = Array.from({ length: 100 }, (_, i) => `k${i}`);
  const valueFiles = {};
  for (let f = 0; f < 11; f += 1) {
    valueFiles[`v${f}.json`] = JSON.stringify(Object.fromEntries(keys.map((k) => [k, value("val", f, k, "Zq8Wx3")])));
  }
  const values = setup(valueFiles, Object.keys(valueFiles).map((file) => json(file, keys)));
  const loaded = loadApprovedSecretSources(values.repo, values.home);
  assert.equal(loaded.secrets.length, KNOWN_SECRETS_MAX);
  assert.match(loaded.sources.at(-1).incomplete, /value budget of 1000 exhausted/);
});

test("issue #130: JSON paths cannot reach the prototype chain", () => {
  const { repo, home } = setup({ "local.json": JSON.stringify({ list: [API_TOKEN] }) }, [
    json("local.json", ["constructor.name", "__proto__.toString", "list.length", "list.0"])
  ]);
  const loaded = loadApprovedSecretSources(repo, home);
  assert.deepEqual(loaded.secrets, [API_TOKEN]);
  assert.equal(loaded.sources[0].missing, 2); // constructor, __proto__
  assert.equal(loaded.sources[0].skipped, 1); // list.length is a number
});

test("issue #130: properties are parsed as data, with no expansion", () => {
  const entries = parseProperties(
    [
      "# comment",
      "! also a comment",
      "plain=one",
      "colon: two",
      "space three",
      "  indented = four  ",
      "expanded=${plain}",
      "multi=first \\",
      "    second",
      "escaped\\ key=\\u0041\\tB",
      "dup=old",
      "dup=new",
      "empty="
    ].join("\n")
  );
  assert.equal(entries.get("plain"), "one");
  assert.equal(entries.get("colon"), "two");
  assert.equal(entries.get("space"), "three");
  assert.equal(entries.get("indented"), "four  ");
  assert.equal(entries.get("expanded"), "${plain}");
  assert.equal(entries.get("multi"), "first second");
  assert.equal(entries.get("escaped key"), "A\tB");
  assert.equal(entries.get("dup"), "new");
  assert.equal(entries.get("empty"), "");
});

test("issue #130: describe reports identity and counts only, and writes nothing", () => {
  const { base, repo, home } = setup({ "local.json": JSON.stringify({ token: API_TOKEN }) }, [json("local.json", ["token"])]);
  const described = describeApprovedSecretSources(repo, home);
  assert.deepEqual(described, {
    configured: true,
    inRepo: true,
    sources: [{ file: "local.json", format: "json", keys: 1, count: 1, missing: 0, skipped: 0, incomplete: null }],
    errors: [],
    secretCount: 1
  });
  assert.doesNotMatch(allOutput(described), new RegExp(API_TOKEN));
  assert.equal(formatApprovedSourceWarnings(described, home), "");

  // Read-only: a home with no ~/.gforge stays without one.
  const bare = join(base, "bare-home");
  mkdirSync(bare);
  describeApprovedSecretSources(repo, bare);
  assert.deepEqual(readdirSync(bare), []);
  assert.deepEqual(describeApprovedSecretSources(null, home).sources, []);
});

test("issue #130: the new rule id is reserved against custom rule packs", () => {
  const { errors } = parseCustomRules(
    JSON.stringify({ rules: [{ id: "hardcoded-known-secret", description: "x", regex: "x" }] })
  );
  assert.match(errors[0], /already used by a built-in rule/);
});
