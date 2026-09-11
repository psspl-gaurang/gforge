import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import test from "node:test";

import {
  GENERIC_SECRET_RULE_ID,
  collectDotenvFiles,
  decodeBlob,
  describeDotenvSources,
  entropyCandidates,
  formatReport,
  isDotenvFile,
  isExpectedGitReadFailure,
  isHeuristicExemptPath,
  isEnvTemplate,
  loadDotenvSecrets,
  matchFilenameRule,
  parseAllowlist,
  scanStaged,
  scanText,
  shannonEntropy
} from "../src/scanner.js";

const opts = { runGitleaks: false };
const ruleIds = (path, text, extra = {}) => scanText(path, text, { ...opts, ...extra }).map((f) => f.ruleId);

test("detects a generic keyword=value secret (the DB_PASS regression)", () => {
  assert.ok(ruleIds("config.txt", "DB_PASS=psspl@443e").includes("generic-secret-assignment"));
  assert.ok(ruleIds("a.yml", 'password: "hunter2longvalue"').includes("generic-secret-assignment"));
  assert.ok(ruleIds("a.js", "const api_key = 'abcd1234efgh'").includes("generic-secret-assignment"));
});

test("detects a variety of hardcoded password/credential assignments", () => {
  assert.ok(ruleIds("a.js", 'const password = "s3cr3tValue!"').includes("generic-secret-assignment"));
  assert.ok(ruleIds("a.py", "PASSWORD = 'hunter2value'").includes("generic-secret-assignment"));
  assert.ok(ruleIds("a.json", '"client_secret": "abcd1234efgh5678"').includes("generic-secret-assignment"));
  assert.ok(ruleIds("a.ini", "connection_string=Server=db;Pwd=abcd1234;").includes("generic-secret-assignment"));
  assert.ok(ruleIds("a.txt", "Authorization: Bearer abcdef2345token").includes("generic-secret-assignment"));
  assert.ok(ruleIds("a.env", "SESSION_KEY=9f8e7d6c5b4a3210").includes("generic-secret-assignment"));
});

test("issue #27: a compound camelCase identifier does not hide the credential keyword", () => {
  // The exact reported cases: the keyword sits mid-identifier, preceded by a
  // lowercase letter, which the original boundary (start-of-line or
  // non-alphanumeric) never matched.
  assert.ok(ruleIds("a.js", "const apiSecretKey = 'Sup3rS3cretV4lue';").includes(GENERIC_SECRET_RULE_ID));
  assert.ok(ruleIds("a.js", "const wbAccessToken = 'Sup3rS3cretV4lue';").includes(GENERIC_SECRET_RULE_ID));
  assert.ok(ruleIds("a.js", "const clientSecretValue = 'Sup3rS3cretV4lue';").includes(GENERIC_SECRET_RULE_ID));
  assert.ok(ruleIds("a.js", "apiSecretKey: 'Sup3rS3cretV4lue',").includes(GENERIC_SECRET_RULE_ID));
  // A real occurrence from the issue: a commented-out assignment using the
  // same naming convention still finds the keyword.
  assert.ok(ruleIds("a.js", "// const wbAccessToken = 'Sup3rS3cretV4lue';").includes(GENERIC_SECRET_RULE_ID));
});

test("issue #27: the compound-identifier match stays bounded, not a license to match anything containing the keyword", () => {
  // "ApiKey" is a coincidental prefix of "Keyboard" here - the word after it
  // is lowercase, not a fresh camelCase segment, so it must not be treated as
  // a continuation of the keyword match.
  assert.equal(ruleIds("a.js", "const ApiKeyboardShortcut = 'cmd+k';").length, 0);
  // Only one trailing camelCase segment is tolerated (the "Value" in
  // clientSecretValue) - a longer unrelated compound tail must not let the
  // match run all the way to a distant, unrelated "=".
  assert.equal(ruleIds("a.js", "apiSecretKeyRotationInterval = 86400;").length, 0);
  // Snake_case identifiers where the keyword is not the last segment before
  // "=" must keep behaving exactly as before this fix (no new match, since
  // this shape was never part of the reported bug and camelCase-only
  // continuation deliberately does not extend to underscore segments).
  assert.equal(ruleIds("a.js", "password_reset_enabled = true;").length, 0);
});

test("does not flag credential keys wired to env vars / references (well-written config)", () => {
  // The critical real-world case: Sequelize/config files that read secrets from
  // the environment must NOT be blocked.
  assert.equal(ruleIds("config/db.js", "password: process.env.DB_PASSWORD,").length, 0);
  assert.equal(ruleIds("config/db.js", "password: config.get('db.password'),").length, 0);
  assert.equal(ruleIds("config/db.js", "password: getSecret('db'),").length, 0);
  assert.equal(ruleIds("config/db.js", 'password: `${DB_PASSWORD}`,').length, 0);
  assert.equal(ruleIds("app.py", "password = os.environ['DB_PASSWORD']").length, 0);
  assert.equal(ruleIds("app.sh", "PASSWORD=$DB_PASSWORD").length, 0);
  assert.equal(ruleIds("config.json", '"password": "DB_PASSWORD"').length, 0); // env-name placeholder
  assert.equal(ruleIds(".env.example", "DB_PASSWORD=changeme").length, 0);
});

test("still flags hardcoded credentials in config files (Sequelize-style)", () => {
  assert.ok(ruleIds("config/config.json", '"password": "MyS3cretDbPass"').includes("generic-secret-assignment"));
  assert.ok(ruleIds("config/db.js", "password: 'MyS3cretDbPass',").includes("generic-secret-assignment"));
});

test("in code, an unquoted bare identifier is a variable reference, not a literal", () => {
  assert.equal(ruleIds("auth.js", "user.password = hashedPassword").length, 0);
  assert.equal(ruleIds("auth.ts", "const password = hashedValue;").length, 0);
  assert.equal(ruleIds("login.py", "password = user_input").length, 0);
  // But a quoted literal in code is still a hardcoded secret.
  assert.ok(ruleIds("auth.js", 'const password = "hunter2secret";').includes("generic-secret-assignment"));
});

test("in config/env/yaml files, an unquoted bare word is a literal and is flagged", () => {
  assert.ok(ruleIds(".env", "PASSWORD=hunter2secret").includes("generic-secret-assignment"));
  assert.ok(ruleIds("app.yml", "password: hunter2secret").includes("generic-secret-assignment"));
  assert.ok(ruleIds("db.properties", "db.password=hunter2secret").includes("generic-secret-assignment"));
});

test("detects provider tokens and private keys", () => {
  assert.ok(ruleIds("a", `ghp_${"a".repeat(36)}`).includes("github-pat"));
  assert.ok(ruleIds("a", "AKIAIOSFODNN7EXAMPLE").includes("aws-access-key-id"));
  assert.ok(ruleIds("a", `sk_live_${"a".repeat(24)}`).includes("stripe-secret-key"));
  assert.ok(ruleIds("a", `AIza${"A1b2".repeat(8)}xyz`).includes("google-api-key"));
  assert.ok(ruleIds("a", "-----BEGIN RSA PRIVATE KEY-----").includes("private-key"));
});

// A real Azure Storage account key is a 512-bit key, so base64 is always 86
// characters plus "==" padding. This one decodes to readable filler text.
const AZURE_ACCOUNT_KEY = "Z2ZvcmdlLWZha2UtYXp1cmUtc3RvcmFnZS1rZXktZm9yLXRlc3RzLWRvLW5vdC11c2UtMDAwMDAwMDAwMDAwMA==";
const ENTRA_SECRET = "8Xy7Q~aBcDeFgHiJkLmNoPqRsTuVwXyZ012345aB"; // 40 chars, tilde early

test("issue #28: detects Azure Storage, Entra ID and Vonage credentials by name", () => {
  const connectionString = `DefaultEndpointsProtocol=https;AccountName=store;AccountKey=${AZURE_ACCOUNT_KEY};EndpointSuffix=core.windows.net`;
  assert.ok(ruleIds("a.js", `const cs = "${connectionString}";`).includes("azure-storage-key"));
  assert.ok(ruleIds(".env", `AZURE_STORAGE_CONNECTION_STRING=${connectionString}`).includes("azure-storage-key"));

  assert.ok(ruleIds("a.js", `const s = "${ENTRA_SECRET}";`).includes("azure-entra-client-secret"));
  // The point of a named rule: it does not depend on the variable being called
  // something incriminating, which is how the generic layer is evaded.
  assert.ok(ruleIds("a.js", `const cfg = { v: "${ENTRA_SECRET}" };`).includes("azure-entra-client-secret"));

  // Vonage's own query-parameter form, and the SCREAMING_SNAKE env form.
  assert.ok(
    ruleIds("a.js", 'fetch("https://rest.nexmo.com/sms/json?api_key=a1b2c3d4&api_secret=aBcDeF1234567890");')
      .includes("vonage-api-secret")
  );
  assert.ok(ruleIds(".env", "VONAGE_API_SECRET=aBcDeF1234567890").includes("vonage-api-secret"));
  // The SDK's positional (key, secret) constructor carries no credential
  // keyword at all, so nothing else in the pipeline catches it.
  assert.ok(
    ruleIds("a.js", 'const v = new Vonage("a1b2c3d4", "abcdefghijklmnop");').includes("vonage-api-secret")
  );
});

test("issue #28: the new provider rules run where the heuristic layers are skipped", () => {
  // This is what a named rule buys over generic/entropy. Documentation and
  // generated output skip the two heuristic layers by design (issue #24), so
  // before these rules an Azure key pasted into a README was missed entirely.
  assert.ok(ruleIds("README.md", `AccountKey=${AZURE_ACCOUNT_KEY}`).includes("azure-storage-key"));
  assert.ok(ruleIds("docs/setup.md", `client secret ${ENTRA_SECRET}`).includes("azure-entra-client-secret"));
  assert.ok(
    ruleIds("dist/bundle.js", 'new Vonage("a1b2c3d4", "abcdefghijklmnop")').includes("vonage-api-secret")
  );
});

test("issue #28: the new rules stay off look-alike values", () => {
  // Entra secrets are exactly 40 characters; that discipline is what keeps the
  // rule off ordinary strings that happen to contain a tilde.
  for (const length of [38, 39, 41, 50]) {
    const nearMiss = `8Xy7Q~${"a".repeat(length - 6)}`;
    assert.equal(ruleIds("a.js", `const s = "${nearMiss}";`).includes("azure-entra-client-secret"), false, `len ${length}`);
  }
  assert.equal(ruleIds("a.js", 'const p = "~/Library/Application Support/Code/User/x";').includes("azure-entra-client-secret"), false);
  assert.equal(
    ruleIds("a.js", 'const sha = "0123456789abcdef0123456789abcdef01234567";').includes("azure-entra-client-secret"),
    false
  );

  // A bare 16-character run is far too common to flag on shape alone - it
  // occurs over a hundred times in this repository's own source - so the
  // Vonage rule anchors on something Vonage-specific instead.
  assert.equal(ruleIds("a.js", "const id = 'a1b2c3d4e5f6g7h8';").includes("vonage-api-secret"), false);
  // A reference is not a hardcoded secret.
  assert.equal(ruleIds("a.js", "const u = `?api_secret=${process.env.VONAGE_SECRET}`;").includes("vonage-api-secret"), false);
  // Truncated/short values are not account keys.
  assert.equal(ruleIds("a.js", 'const k = "AccountKey=tooshort==";').includes("azure-storage-key"), false);
});

test("issue #81: every credential assignment on a line is examined, not just the first", () => {
  // The gap: each candidate's captured value runs to end of line, so on this
  // line the FIRST candidate's value is "process.env.TOKEN, password: ..." -
  // which correctly reads as an env reference. Returning at that point meant
  // the hardcoded password after it was never looked at, while the identical
  // secret on its own line was caught.
  const sameLine = 'token: process.env.TOKEN, password: "S3cret!789"';
  const splitLines = 'token: process.env.TOKEN,\npassword: "S3cret!789"';
  assert.ok(ruleIds("a.ts", sameLine).includes(GENERIC_SECRET_RULE_ID));
  assert.ok(ruleIds("a.ts", splitLines).includes(GENERIC_SECRET_RULE_ID));

  // One-line object literals are the common real-world shape of this.
  assert.ok(
    ruleIds("a.ts", '{ apiKey: process.env.API_KEY, apiSecret: "aX9kQm2pLw8vRt4z" }').includes(GENERIC_SECRET_RULE_ID)
  );
  // The secret can sit anywhere on the line, not only last.
  assert.ok(
    ruleIds("a.ts", '{ password: "S3cret!789", token: process.env.T }').includes(GENERIC_SECRET_RULE_ID)
  );
  assert.ok(
    ruleIds("a.ts", '{ a: 1, token: process.env.T, user: "bob", password: "S3cret!789" }').includes(GENERIC_SECRET_RULE_ID)
  );
});

test("issue #81: examining every candidate does not start flagging safe lines", () => {
  // The risk of looking past the first match is new false positives, so the
  // value-level judgement still has to clear each one independently.
  assert.equal(ruleIds("a.ts", "token: process.env.TOKEN, password: process.env.PW").length, 0);
  assert.equal(ruleIds("config/db.js", "password: config.get('db.password'), token: getSecret('t')").length, 0);
  assert.equal(ruleIds("a.ts", '{ apiKey: process.env.API_KEY, apiSecret: process.env.API_SECRET }').length, 0);
  // Placeholders stay exempt wherever they appear on the line.
  assert.equal(ruleIds(".env.example", "DB_PASSWORD=changeme, API_TOKEN=your_token_here").length, 0);
});

// A line still yields at most one finding, so a multi-secret line does not
// produce duplicate noise for what a developer fixes in one edit.
test("issue #81: a line with two hardcoded secrets still reports once", () => {
  const findings = scanText("a.ts", '{ password: "S3cret!789", apiSecret: "aX9kQm2pLw8vRt4z" }', { runGitleaks: false })
    .filter((f) => f.ruleId === GENERIC_SECRET_RULE_ID);
  assert.equal(findings.length, 1);
});

test("detects credentials embedded in a URL", () => {
  assert.ok(ruleIds("a", "postgres://user:supersecret@db:5432/app").includes("basic-auth-url"));
});

test("detects unnamed high-entropy strings", () => {
  assert.ok(ruleIds("a", 'x = "Zx9Kq2mVbN7pLwR4tYaSdFgHjKlPoIuY"').includes("high-entropy-string"));
});

test("does not flag bare references or ordinary code (false positives)", () => {
  assert.equal(ruleIds("a", "const t = process.env.GITHUB_TOKEN").length, 0);
  assert.equal(ruleIds("a", "token: ${{ secrets.GITHUB_TOKEN }}").length, 0);
  assert.equal(ruleIds("a", "the quick brown fox jumps over the lazy dog").length, 0);
  assert.equal(ruleIds("a", "password=").length, 0);
});

test("entropy ignores git SHAs, UUIDs, and lockfiles", () => {
  assert.ok(!ruleIds("a", "rev 9e3c1f2a5b7d8e0a1c2b3d4e5f60718293a4b5c6").includes("high-entropy-string"));
  assert.ok(!ruleIds("a", "id=123e4567-e89b-12d3-a456-426614174000").includes("high-entropy-string"));
  assert.ok(!ruleIds("package-lock.json", `"integrity":"sha512-${"Zx9Kq2mV".repeat(6)}"`).includes("high-entropy-string"));
});

test("entropy does not flag ordinary long identifiers (issue #17)", () => {
  for (const id of [
    "buildBookingMatchWhereClause",
    "ManagerDashboardUpcomingAnalyticsCard",
    "UpdateLocationSummaryEmailPreferencesDto",
    "fetchRawAudioFromPBX"
  ]) {
    assert.equal(ruleIds("service.ts", `  async ${id}(input) {`).includes("high-entropy-string"), false, id);
  }
  // But an identifier-shaped string that is actually random (vowel-sparse) is caught.
  assert.ok(ruleIds("a.ts", 'const k = "Zx9Kq2mVbN7pLwR4tYaSdFgHjKlPoIuY"').includes("high-entropy-string"));
});

// --- entropy tokenizer: paths vs. base64 (issue #1) ------------------------
// A long path used to be scored as one token, so the concatenation crossed the
// threshold even when every identifier in it was ordinary. Fixtures below are
// real lines from an audited monorepo.

const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // canonical AWS example key, 40 b64 chars, two "/"
const B64URL_TOKEN = "kM8Yq-3xZv7TbN2wRp5LsJ4hGf9dCe1aUiOoPqXyZmA"; // 43 chars, "-" and "_" are alphabet here

test("entropy scores path segments, not the whole path", () => {
  // The concatenated path scores 4.229; the bare identifier scores 3.825.
  const importLine =
    "import GlobalFilterSummaryTrigger from 'src/components/GlobalFilterSidebar/GlobalFilterSummaryTrigger'";
  assert.equal(ruleIds("Layout.tsx", importLine).length, 0);
  assert.equal(ruleIds("x.tsx", "from 'src/components/agent-dashboard/AgentCallVolumeChart'").length, 0);
  assert.equal(ruleIds("x.ts", " * documents/modules/webhook-implementation/bug-fix/).").length, 0);
  // Dotfile directory segments, i.e. build caches.
  assert.equal(ruleIds("x.js", "// node_modules/.vite/deps/chunk-QWERTYUIOP").length, 0);
  // Version and acronym segments carry digits without being random.
  assert.equal(ruleIds("x.ts", "from 'client/src/api/v2/endpoints/CustomerBookingEndpoints'").length, 0);
  assert.equal(ruleIds("x.ts", "from 'src/modules/oauth2/strategies/GoogleOAuth2Strategy'").length, 0);
  assert.equal(ruleIds("x.ts", "from 'src/aws/s3/S3StorageAdapterFactory'").length, 0);
});

test("entropy leaves ordinary path-shaped prose alone", () => {
  // Markdown links, CDN URLs, scoped package names, and deep relative paths all
  // tokenize as one long "/"-joined string.
  assert.equal(ruleIds("README.md", "See [the guide](documents/modules/webhook-implementation/setup/).").length, 0);
  assert.equal(ruleIds("index.html", '<script src="https://cdn.example.com/static/js/main-chunk"></script>').length, 0);
  assert.equal(ruleIds("x.ts", "import { thing } from '@babel/plugin-transform-runtime/lib/helpers'").length, 0);
  assert.equal(ruleIds("x.ts", "from '../../../shared/infrastructure/persistence/RepositoryFactory'").length, 0);
  assert.equal(ruleIds("Makefile", "OUT := build/artifacts/linux-amd64/release-bundle").length, 0);
});

test("path splitting does not hide base64 secrets containing a slash", () => {
  // The AWS key's segments look identifier-ish; only the lowercase-ratio gate
  // keeps it out of the path branch. Losing this is the whole risk of the fix.
  assert.ok(ruleIds("a.ts", `const k = "${AWS_SECRET_KEY}"`).includes("high-entropy-string"));
  assert.ok(ruleIds("a.env", `AWS_SECRET_ACCESS_KEY=${AWS_SECRET_KEY}`).includes("high-entropy-string"));
  // base64url shapes, including one sitting in a URL path — the case that rules
  // out also splitting on "-" and "_".
  assert.ok(ruleIds("a.ts", `sig = '${B64URL_TOKEN}'`).includes("high-entropy-string"));
  assert.ok(ruleIds("a.ts", `url = '/auth/reset/${B64URL_TOKEN}'`).includes("high-entropy-string"));
  assert.ok(ruleIds("a.ts", `url = '/api/v1/token/${B64URL_TOKEN}'`).includes("high-entropy-string"));
  // Padded base64 with slashes, and a long opaque blob.
  assert.ok(ruleIds("a.ts", 'blob = "Zm9vL2Jhci9iYXo/cXV4Kzk4NzY1NDMyMTBhYmNkZWY="').includes("high-entropy-string"));
});

test("a high-entropy segment inside a path is still flagged", () => {
  // Splitting must not blanket-exempt anything containing a "/". A hashed
  // filename is a real (if low-value) hit: the segment alone scores 4.316.
  assert.ok(ruleIds("index.html", 'href="/assets/vendor-apexcharts-BlCFUAhW.js"').includes("high-entropy-string"));
  // A secret concatenated onto a legitimate path prefix stays visible.
  assert.ok(ruleIds("a.ts", `const u = 'src/components/${AWS_SECRET_KEY}'`).includes("high-entropy-string"));
});

test("a path and a secret on the same line still yields a finding", () => {
  const line = `import x from 'src/components/agent-dashboard/AgentCallVolumeChart'; const k = "${AWS_SECRET_KEY}";`;
  assert.ok(ruleIds("x.ts", line).includes("high-entropy-string"));
});

test("entropyCandidates decomposes paths and leaves opaque tokens whole", () => {
  assert.deepEqual(entropyCandidates("src/components/GlobalFilterSidebar/GlobalFilterSummaryTrigger"), [
    "src",
    "components",
    "GlobalFilterSidebar",
    "GlobalFilterSummaryTrigger"
  ]);
  // Leading and trailing separators must not produce empty candidates.
  assert.deepEqual(entropyCandidates("/documents/modules/webhook-implementation/"), [
    "documents",
    "modules",
    "webhook-implementation"
  ]);
  // Not paths: no separator, a single segment, base64 padding (=), or a segment
  // that is long and random rather than a name are all scored whole.
  assert.deepEqual(entropyCandidates(AWS_SECRET_KEY), [AWS_SECRET_KEY]);
  assert.deepEqual(entropyCandidates(B64URL_TOKEN), [B64URL_TOKEN]);
  assert.deepEqual(entropyCandidates("Zx9Kq2mVbN7pLwR4tYaSdFgHjKlPoIuY"), ["Zx9Kq2mVbN7pLwR4tYaSdFgHjKlPoIuY"]);
  assert.deepEqual(entropyCandidates("/onlyonesegmentislongenough"), ["/onlyonesegmentislongenough"]);
  assert.deepEqual(entropyCandidates("aGVsbG8=/d29ybGQ="), ["aGVsbG8=/d29ybGQ="]);
  // SCREAMING_SNAKE_CASE segments are clean const/env names, not base64 (which is
  // mixed-case), so an all-caps path decomposes per-segment too (issue #19).
  assert.deepEqual(entropyCandidates("SRC/COMPONENTS/GLOBALFILTERSUMMARYTRIGGER"), [
    "SRC",
    "COMPONENTS",
    "GLOBALFILTERSUMMARYTRIGGER"
  ]);
});

test("issue #24: translation catalogues, docs and build output skip the heuristic rules", () => {
  // "Password": "Passwort" is the normal shape of a translation entry.
  assert.equal(ruleIds("client/src/translations/hi/common.json", '  "Password": "पासवर्ड",').length, 0);
  assert.equal(ruleIds("client/src/translations/hi/common.json", '  "clientSecret": "क्लाइंट सीक्रेट",').length, 0);
  assert.equal(ruleIds("client/src/translations/en/common.json", '  "clientSecret": "Client Secret",').length, 0);
  assert.equal(ruleIds("client/src/translations/de/common.json", '  "token": "Authentifizierungstoken",').length, 0);
  assert.equal(ruleIds("client/src/translations/fr/common.json", `  "token": "Jeton d'authentification",`).length, 0);
  assert.equal(ruleIds("server/src/i18n/en/responseMessage.json", '  "invalidPassword": "The password you entered is incorrect",').length, 0);
  assert.equal(ruleIds("resources/lang/es/auth.php", "'password' => 'La contrasena es incorrecta',").length, 0);
  // Docs and build output.
  assert.equal(ruleIds("server/src/core/logger/README.md", "password: your-database-password").length, 0);
  assert.equal(ruleIds("documents/features/auth.md", "| clientSecret | shhh-do-not-share-this |").length, 0);
  assert.equal(ruleIds("client/dist/index.html", 'var token="anonymous-public-widget-token";').length, 0);
  // The generic rule now has the skip list the entropy rule already had.
  assert.equal(ruleIds("server/package-lock.json", '  "token": "abcd1234efgh5678",').length, 0);
  assert.equal(ruleIds("a/b.min.js", 'var password="abcd1234efgh5678";').length, 0);
});

test("issue #24: exemptions are path-scoped and never disable the high-confidence rules", () => {
  // Provider rules, which carry no false-positive risk, still fire everywhere.
  for (const path of [
    "client/dist/index.html",
    "docs/setup.md",
    "client/src/translations/hi/common.json",
    "server/package-lock.json"
  ]) {
    assert.ok(ruleIds(path, "AKIAIOSFODNN7EXAMPLE").includes("aws-access-key-id"), path);
    assert.ok(ruleIds(path, `k = "sk_live_${"a".repeat(24)}"`).includes("stripe-secret-key"), path);
    assert.ok(ruleIds(path, "-----BEGIN RSA PRIVATE KEY-----").includes("private-key"), path);
  }
  // Lookalike directory names are ordinary source and stay fully scanned.
  for (const path of [
    "src/distributor/api.ts",
    "src/building/service.ts",
    "src/outbound/mailer.ts",
    "src/language/parser.ts",
    "server/src/i18nUtils.ts",
    "config.txt"
  ]) {
    assert.ok(ruleIds(path, 'const password = "S3cr3tDbP4ssw0rd";').includes(GENERIC_SECRET_RULE_ID), path);
  }
  assert.equal(isHeuristicExemptPath("client/src/translations/hi/common.json"), "i18n");
  assert.equal(isHeuristicExemptPath("README.md"), "docs");
  assert.equal(isHeuristicExemptPath("client/dist/index.html"), "generated");
  assert.equal(isHeuristicExemptPath("src/config/db.js"), null);
  // Windows separators classify the same way.
  assert.equal(isHeuristicExemptPath("client\\dist\\index.html"), "generated");
  // The exclusions can be switched off entirely.
  assert.equal(isHeuristicExemptPath("client/dist/index.html", { GFORGE_NO_DEFAULT_EXCLUDES: "1" }), null);
});

test("issue #24: the non-Latin guard does not hide a real credential", () => {
  // A translated label in a data file is not a secret...
  assert.equal(ruleIds("client/messages/hi.json", '"Password": "पासवर्ड"').length, 0);
  // ...but a human-chosen password in application code still is, script regardless.
  assert.ok(ruleIds("app.js", 'const password = "пароль123";').includes(GENERIC_SECRET_RULE_ID));
  assert.ok(ruleIds("app.js", 'const password = "пароль";').includes(GENERIC_SECRET_RULE_ID));
});

test("issue #19: f-string interpolation and SCREAMING_SNAKE path segments are not secrets", () => {
  // 1) f-string / interpolated-string values are references, not literals.
  assert.equal(ruleIds("voice_changer.py", `    headers = {"Authorization": f"Bearer {token}"}`).length, 0);
  assert.equal(ruleIds("a.py", `auth = f"Bearer {access_token}"`).length, 0);
  assert.equal(ruleIds("a.cs", `password = $"{dbPassword}"`).length, 0);
  // 2) a shell/env var path with a SCREAMING_SNAKE segment is not high-entropy.
  assert.equal(
    ruleIds("setup.sh", `  python -m pip install -r "$BACKEND_DIR/requirements.txt"`).includes("high-entropy-string"),
    false
  );
  assert.equal(entropyCandidates("BACKEND_DIR/requirements").length, 2);
  // But real hardcoded secrets are still caught.
  assert.ok(ruleIds("a.py", 'password = "MyR3alHardcodedValue"').includes("generic-secret-assignment"));
  assert.ok(ruleIds("a.ts", `const k = "${AWS_SECRET_KEY}"`).includes("high-entropy-string"));
});

test("issue #23: the generic rule does not mine bogus values out of log statements", () => {
  // The keyword and its ':' sit INSIDE a string literal, so the quote that follows
  // is that string's CLOSING quote -- previously mistaken for the start of a value.
  assert.equal(ruleIds("sw.ts", "console.error('[AuthManager] Failed to clear auth:', error);").length, 0);
  assert.equal(ruleIds("sw.ts", "console.error('[SERVICE_WORKER] Failed to clear token:', error);").length, 0);
  // Here the stray quote pairs with a later, unrelated literal, yielding the
  // expression fragment ", authState.token ?".
  assert.equal(
    ruleIds("conn.ts", "console.log('[Connection] Using auth token:', authState.token ? 'Present' : 'Missing');").length,
    0
  );
  assert.equal(ruleIds("log.ts", "logger.info('auth token: ' + t)").length, 0);
});

test("issue #23: labels, auth schemes, and route templates are not credentials", () => {
  // A value that is just the name of the thing is a label.
  assert.equal(ruleIds("routes.ts", 'export const AUTH = "auth";').length, 0);
  assert.equal(ruleIds("consts.ts", 'BEARER: "Bearer"').length, 0);
  // An Authorization value names its scheme first; judge what follows it.
  assert.equal(ruleIds("README.md", '-H "Authorization: Bearer YOUR_JWT_TOKEN"').length, 0);
  // A route template is a placeholder, not a value.
  assert.equal(ruleIds("routes.ts", 'export const CHANGE_PASSWORD = "changepassword/:uuid";').length, 0);
  // A constant whose value just restates its own name is a label.
  assert.equal(
    ruleIds("keys.ts", 'export const CALL_HISTORY_SKIP_DEFAULT_FILTERS_SESSION_KEY = "call-history-skip-default-filters";').length,
    0
  );
});

test("issue #23: the same shapes carrying a REAL credential are still blocked", () => {
  // The scheme is stripped, not trusted: a real token after it must still flag.
  assert.ok(ruleIds("a.txt", "Authorization: Bearer abcdef2345token").includes(GENERIC_SECRET_RULE_ID));
  assert.ok(ruleIds("a.sh", 'curl -H "Authorization: Basic YWRtaW46czNjcjN0"').includes(GENERIC_SECRET_RULE_ID));
  assert.ok(ruleIds("c.ts", 'BEARER: "Bearer aX9kQm2pLw8vRt4z"').includes(GENERIC_SECRET_RULE_ID));
  // A label-shaped constant name with a real value is still a hardcoded secret.
  assert.ok(ruleIds("c.ts", 'const AUTH = "s3cr3tAuthValue123";').includes(GENERIC_SECRET_RULE_ID));
  // A route prefix does not launder a token appended to it: one random-looking
  // segment means the path is not a template. Lowercase shapes matter most here --
  // hex beginning a-f and all-lowercase tokens are lowercase like a route word,
  // and entropy alone cannot separate them.
  assert.ok(
    ruleIds("r.ts", 'export const TOKEN = "changepassword/:uuid/aX9kQm2pLw8vRt4zNc";').includes(GENERIC_SECRET_RULE_ID)
  );
  assert.ok(
    ruleIds("r.ts", 'const token = "changepassword/:uuid/a3f9b2c8d1e4f7a2b9c3d8e1f4a7b2c9";').includes(GENERIC_SECRET_RULE_ID)
  );
  assert.ok(
    ruleIds("r.ts", 'const token = "changepassword/:uuid/qwrtypsdfghjklzxcvbnmqwe";').includes(GENERIC_SECRET_RULE_ID)
  );
  // A descriptive key name does not launder a real value: the key-echo rule only
  // fires when the value is spelled out INSIDE the key, never the reverse.
  assert.ok(
    ruleIds("keys.ts", 'export const CALL_HISTORY_SESSION_KEY = "aX9kQm2pLw8vRt4zNc";').includes(GENERIC_SECRET_RULE_ID)
  );
  // A quoted value is still read normally when the quotes are balanced.
  assert.ok(ruleIds("a.sh", `PASSWORD="it's-a-s3cr3t"`).includes(GENERIC_SECRET_RULE_ID));
  assert.ok(ruleIds("a.js", `const token = "abc123def456" // user's key`).includes(GENERIC_SECRET_RULE_ID));
});

test("issue #45: an all-lowercase random secret after a route-template prefix is still caught", () => {
  // The exact reported gap: a long, all-lowercase random-looking segment used
  // to pass the route-word check on vowel ratio alone (~35% here, comfortably
  // over the 25% bar) even though it is not an English word - a long run of
  // consecutive consonants ("nqwqdln") gives it away where vowel ratio alone
  // could not.
  const secret = "whoquiueaqmhonqwqdln";
  assert.ok(ruleIds("r.ts", `export const TOKEN = "reset/:uuid/${secret}";`).includes(GENERIC_SECRET_RULE_ID));
  // A short (<8 char) segment is no longer a completely free pass regardless
  // of content: previously any lowercase segment under 8 chars was treated as
  // route-word-shaped with zero content check, so a short but unmistakably
  // non-word consonant run ("xzpqrtv", 7-in-a-row) rode along for free as soon
  // as the value also contained a genuine ":param" segment elsewhere.
  assert.ok(ruleIds("r.ts", 'export const TOKEN = "resetpw/:id/xzpqrtv";').includes(GENERIC_SECRET_RULE_ID));
  // Real compound route words - including consonant-heavy ones - must still be
  // exempt; this closes a real gap without regressing the legitimate case.
  // "encrypt" is the boundary case that matters: it scores exactly 6 (y is not
  // counted as a vowel, so n-c-r-y-p-t is a 6-run), as do "xmlrpc", "rhythm"
  // and "nightschool" - so the consonant bar must sit above 6, not at it.
  assert.equal(ruleIds("routes.ts", 'export const RESET_TOKEN = "api/:version/encrypt";').length, 0);
  assert.equal(ruleIds("routes.ts", 'export const RPC_TOKEN = "api/:version/xmlrpc";').length, 0);
  assert.equal(ruleIds("routes.ts", 'export const HEALTH = "api/v1/healthcheck";').length, 0);
  assert.equal(ruleIds("routes.ts", 'export const SUB = "account/subscription";').length, 0);
});

test("issue #37: appending the literal secret to a credential-keyword identifier is not a self-referential label", () => {
  const secret = "hunter2!Real9";
  // Same secret, same shape as the legitimate self-label exemption (the value
  // is substring-contained in the key) - but the "extra" part of the key is
  // the very credential keyword that made this a hardcoded-secret candidate
  // in the first place, and the value itself is not a plain word/slug.
  assert.ok(ruleIds("config.js", `const ${secret}_password = "${secret}";`).includes(GENERIC_SECRET_RULE_ID));
  // Digits alone are enough to disqualify the exemption, even with no symbol
  // character anywhere in the secret.
  assert.ok(ruleIds("config.js", 'const A1b2c3d4e5_password = "A1b2c3d4e5";').includes(GENERIC_SECRET_RULE_ID));
  // The legitimate exemption this rule exists for must still hold: a plain
  // word/slug that merely restates its own name is still a label, not a
  // credential.
  assert.equal(ruleIds("config.js", 'const SESSION_KEY = "session-key";').length, 0);
  assert.equal(
    ruleIds("keys.ts", 'export const CALL_HISTORY_SKIP_DEFAULT_FILTERS_SESSION_KEY = "call-history-skip-default-filters";')
      .length,
    0
  );
});

test("issue #68: vowel-poor real route words are still route templates", () => {
  // The 25% vowel ratio is an English-word bar, and real route vocabulary sits
  // under it: "graphqlws" (graphql-ws, a real library) carries 1 vowel in 9
  // letters, "transcript" and "postgresql" 2 in 10, "playlists" 2 in 9.
  assert.equal(ruleIds("routes.ts", 'export const WS_TOKEN = "api/:version/graphqlws";').length, 0);
  assert.equal(ruleIds("routes.ts", 'export const KEY = "media/:id/transcript";').length, 0);
  assert.equal(ruleIds("routes.ts", 'export const TOKEN = "users/:id/playlists";').length, 0);
  assert.equal(ruleIds("routes.ts", 'export const AUTH = "webhooks/:id/callbacks";').length, 0);
  assert.equal(ruleIds("routes.ts", 'export const SECRET = "db/:name/postgresql";').length, 0);
});

test("issue #68: a route prefix still does not launder a real secret", () => {
  // The vowel ratio is unchanged for segments long enough to hold a credential,
  // so raising the short-segment floor costs no detection at 12+ characters.
  assert.ok(
    ruleIds("r.ts", 'const token = "api/:version/qwrtplkjhgfdsazx";').includes(GENERIC_SECRET_RULE_ID)
  );
  // Exactly at the new floor: 12 characters is still checked, and 0 vowels fails.
  assert.ok(
    ruleIds("r.ts", 'const token = "api/:version/zxcvbnmlkjhg";').includes(GENERIC_SECRET_RULE_ID)
  );
  // Mixed case, hex and digit-heavy shapes never depended on the vowel ratio.
  assert.ok(
    ruleIds("r.ts", 'const token = "api/:version/aX9kQm2pLw8vRt4zNc";').includes(GENERIC_SECRET_RULE_ID)
  );
  assert.ok(
    ruleIds("r.ts", 'const token = "api/:version/a3f9b2c8d1e4f7a2b9c3d8e1f4a7b2c9";').includes(GENERIC_SECRET_RULE_ID)
  );
  assert.ok(
    ruleIds("r.ts", 'const token = "api/:version/p4ssw0rd1234";').includes(GENERIC_SECRET_RULE_ID)
  );
});

test("inline gforge:allow suppresses a line", () => {
  assert.equal(ruleIds("a", "DB_PASS=psspl@443e # gforge:allow").length, 0);
  assert.equal(ruleIds("a", "DB_PASS=psspl@443e // gitleaks:allow").length, 0);
});

test("filename rules block secret files but allow templates", () => {
  assert.equal(matchFilenameRule(".env")?.id, "secret-file-env");
  assert.equal(matchFilenameRule("app/.env.production")?.id, "secret-file-env");
  assert.equal(matchFilenameRule(".env.example"), null);
  assert.equal(matchFilenameRule("deploy/id_rsa")?.id, "secret-file");
  assert.equal(matchFilenameRule("cert.p12")?.id, "secret-file");
  assert.equal(matchFilenameRule("src/app.js"), null);
});

test("multi-part env templates are templates, not real env files (issue #25)", () => {
  // Only the LAST dot-segment decides. Descriptive template names are the norm.
  for (const p of [
    "server/.env.cron-cdr-backfill.example",
    ".env.local.example",
    ".env.staging.template",
    ".env.ci.sample",
    ".env.example"
  ]) {
    assert.ok(isEnvTemplate(p), `expected template: ${p}`);
    assert.equal(matchFilenameRule(p), null, `expected no filename rule: ${p}`);
  }
  // Real env files must still be blocked — including multi-part ones.
  for (const p of [".env", ".env.production", ".env.local", "app/.env.production.local"]) {
    assert.ok(!isEnvTemplate(p), `expected NOT template: ${p}`);
    assert.equal(matchFilenameRule(p)?.id, "secret-file-env", `expected secret-file-env: ${p}`);
  }
});

test("your_* / *_here placeholders are not credentials (issue #25)", () => {
  // The dotenv layer already knew these were placeholders; the generic rule did
  // not, so committed templates were flagged line by line.
  for (const line of [
    "DB_PASS=your_db_password",
    "PBX_OAUTH_CLIENT_SECRET=your_pbx_oauth_client_secret",
    "API_KEY=your-api-key",
    "SECRET=replace_me_here",
    "TOKEN=my_secret_value"
  ]) {
    assert.ok(!ruleIds("config.txt", line).includes(GENERIC_SECRET_RULE_ID), line);
  }
  // A real value in the same shape of file is still caught.
  assert.ok(ruleIds("config.txt", "DB_PASS=aG9yc2ViYXR0ZXJ5c3RhcGxlMTIz").includes(GENERIC_SECRET_RULE_ID));
  assert.ok(ruleIds("config.txt", "DB_PASS=x+Wux6!wPJVy{2qf}p").includes(GENERIC_SECRET_RULE_ID));
});

test("env templates skip generic/entropy rules but still catch real tokens", () => {
  assert.ok(isEnvTemplate(".env.example"));
  assert.ok(!isEnvTemplate(".env"));
  // Placeholder assignment is allowed in a template...
  assert.equal(scanStaged({ ...opts, allowlist: [], files: [".env.example"], read: () => "SECRET=your-value-here" }).findings.length, 0);
  // ...but a real token is still blocked.
  const real = scanStaged({ ...opts, allowlist: [], files: [".env.example"], read: () => `GITHUB_TOKEN=ghp_${"a".repeat(36)}` });
  assert.ok(real.findings.some((f) => f.ruleId === "github-pat"));
});

test("allowlist skips matching paths", () => {
  const allowlist = parseAllowlist("config.txt\n# comment\n^secrets/");
  const blocked = scanStaged({ ...opts, allowlist, files: ["other.txt"], read: () => "DB_PASS=psspl@443e" });
  assert.ok(blocked.findings.length > 0);
  const allowed = scanStaged({ ...opts, allowlist, files: ["config.txt"], read: () => "DB_PASS=psspl@443e" });
  assert.equal(allowed.findings.length, 0);
  const allowedDir = scanStaged({ ...opts, allowlist, files: ["secrets/prod.txt"], read: () => "DB_PASS=psspl@443e" });
  assert.equal(allowedDir.findings.length, 0);
});

test("report never contains the matched secret value", () => {
  const result = scanStaged({ ...opts, allowlist: [], files: ["config.txt"], read: () => "DB_PASS=psspl@443e" });
  const report = formatReport(result);
  assert.doesNotMatch(report, /psspl@443e/);
  assert.match(report, /config\.txt/);
  assert.match(report, /generic-secret-assignment/);
});

test("detects a bare Twilio auth token only in a Twilio context", () => {
  const token = "0123456789abcdef0123456789abcdef"; // 32 hex, no keyword
  assert.ok(ruleIds("app.js", `const c = twilio(sid, '${token}');`).includes("twilio-auth-token"));
  assert.ok(ruleIds("app.js", `const sid='AC${"a".repeat(32)}';\nconst t='${token}';`).includes("twilio-auth-token"));
  // No Twilio context: a bare 32-hex string (etag/md5) must NOT be flagged.
  assert.equal(ruleIds("hash.js", `const etag = '${token}';`).includes("twilio-auth-token"), false);
  // A 40-hex git SHA must not match the 32-hex token rule even with context.
  assert.equal(
    ruleIds("app.js", "// twilio\nconst sha='9e3c1f2a5b7d8e0a1c2b3d4e5f60718293a4b5c6';").includes("twilio-auth-token"),
    false
  );
});

test("cross-references staged code against .env secret values", () => {
  const token = "0123456789abcdef0123456789abcdef";
  const leak = scanStaged({
    ...opts, allowlist: [], dotenvSecrets: [token],
    files: ["src/twilioClient.js"], read: () => `const client = twilio(sid, "${token}");`
  });
  assert.ok(leak.findings.some((f) => f.ruleId === "hardcoded-dotenv-secret"));
  // The report must not print the value.
  assert.doesNotMatch(formatReport(leak), new RegExp(token));

  const clean = scanStaged({
    ...opts, allowlist: [], dotenvSecrets: [token],
    files: ["clean.js"], read: () => "const answer = 42;"
  });
  assert.equal(clean.findings.length, 0);
});

test("issue #43: a weak/common word behind a credential-shaped key is not extracted as a secret", () => {
  // Real-world false positive: a dev-default value like "password" is
  // exactly the kind of text that also shows up, completely unrelated, in
  // ordinary code (an HTML type="password" attribute). The extracted list
  // (not a hand-picked dotenvSecrets array, which would bypass extraction
  // filtering entirely) is what a real commit is actually checked against.
  const root = makeTree({ ".env": "DEFAULT_PASSWORD=password\n" });
  const secrets = loadDotenvSecrets(root);
  assert.equal(secrets.includes("password"), false);

  const leak = scanStaged({
    ...opts, allowlist: [], dotenvSecrets: secrets,
    files: ["LoginForm.tsx"], read: () => '<input type="password" autoComplete="current-password" />'
  });
  assert.equal(leak.findings.length, 0);
});

test("issue #43: a CSS-shaped hex color is not extracted as a secret", () => {
  // Another real-world false positive: a theme/branding color value in .env,
  // coincidentally matching an unrelated color literal elsewhere.
  for (const envContent of ["THEME_ACCENT_KEY=3a86ff\n", "BRAND_API_KEY=#fff\n", "SECRET_COLOR_TOKEN=a1b2c3d4\n"]) {
    const root = makeTree({ ".env": envContent });
    assert.deepEqual(loadDotenvSecrets(root), [], envContent);
  }

  const root = makeTree({ ".env": "THEME_ACCENT_KEY=3a86ff\n" });
  const secrets = loadDotenvSecrets(root);
  const leak = scanStaged({
    ...opts, allowlist: [], dotenvSecrets: secrets,
    files: ["theme.tsx"], read: () => "export const PRIMARY = '#3a86ff';"
  });
  assert.equal(leak.findings.length, 0);
});

test("issue #43: a genuinely strong secret behind a credential-shaped key is still caught", () => {
  const root = makeTree({ ".env": "REAL_API_TOKEN=aX9kQm2pLw8vRt4zNcQ7\n" });
  const secrets = loadDotenvSecrets(root);
  assert.ok(secrets.includes("aX9kQm2pLw8vRt4zNcQ7"));

  const leak = scanStaged({
    ...opts, allowlist: [], dotenvSecrets: secrets,
    files: ["leak.js"], read: () => 'const t = "aX9kQm2pLw8vRt4zNcQ7";'
  });
  assert.ok(leak.findings.some((f) => f.ruleId === "hardcoded-dotenv-secret"));
});

test("issue #43: the cross-reference respects word boundaries, not a raw substring match", () => {
  const secret = "longenoughsecret1";

  // Embedded as a fragment inside a longer, unrelated identifier: not a match.
  const embedded = scanStaged({
    ...opts, allowlist: [], dotenvSecrets: [secret],
    files: ["a.js"], read: () => 'const x = "prefixlongenoughsecret1suffix";'
  });
  assert.equal(embedded.findings.length, 0);

  // The same value as a standalone token is still caught.
  const standalone = scanStaged({
    ...opts, allowlist: [], dotenvSecrets: [secret],
    files: ["a.js"], read: () => `const x = "${secret}";`
  });
  assert.ok(standalone.findings.some((f) => f.ruleId === "hardcoded-dotenv-secret"));

  // A value bordered by non-identifier punctuation (not itself embedded in a
  // larger word) still matches, same as a plain substring check would.
  const punctuated = scanStaged({
    ...opts, allowlist: [], dotenvSecrets: [secret],
    files: ["a.js"], read: () => `Authorization: Bearer ${secret}!`
  });
  assert.ok(punctuated.findings.some((f) => f.ruleId === "hardcoded-dotenv-secret"));
});

test("cross-references .env files in package subdirectories, not just the repo root", () => {
  // The monorepo layout from issue #26: no root .env at all, one per package.
  const root = makeTree({
    "server/.env": "DB_PASSWORD=Sup3rS3cretMonoValue\n",
    "client/.env.local": "VITE_API_TOKEN=clientTok3nAbcdef123456\n",
    "server/.env.example": "DB_PASSWORD=your_db_password\n", // template: placeholders only
    "node_modules/some-pkg/.env": "PKG_SECRET=vendoredValue1234\n", // another project's secrets
    "dist/.env": "BUILD_SECRET=generatedValue1234\n"
  });

  assert.deepEqual(relativeDotenvFiles(root), ["client/.env.local", "server/.env"]);

  const secrets = loadDotenvSecrets(root);
  assert.ok(secrets.includes("Sup3rS3cretMonoValue"));
  assert.ok(secrets.includes("clientTok3nAbcdef123456"));
  assert.equal(secrets.includes("your_db_password"), false);
  assert.equal(secrets.includes("vendoredValue1234"), false);

  // End to end: a value pasted out of server/.env into server code is blocked.
  const leak = scanStaged({
    ...opts, allowlist: [], dotenvSecrets: secrets,
    files: ["server/src/db.js"], read: () => 'const pw = "Sup3rS3cretMonoValue";'
  });
  assert.ok(leak.findings.some((f) => f.ruleId === "hardcoded-dotenv-secret"));
  assert.doesNotMatch(formatReport(leak), /Sup3rS3cretMonoValue/);
});

test("recognizes real env files and skips placeholder templates", () => {
  assert.ok(isDotenvFile(".env"));
  assert.ok(isDotenvFile("server/.env.production.local"));
  assert.ok(isDotenvFile(".env.staging"));
  assert.equal(isDotenvFile(".env.example"), false);
  assert.equal(isDotenvFile(".env.local.template"), false);
  assert.equal(isDotenvFile("env"), false);
  assert.equal(isDotenvFile("environment.js"), false);
});

test("bounds the .env walk so a deep tree cannot stall a commit", () => {
  const root = makeTree({
    "a/b/c/d/e/.env": "DEEP_TOKEN=deepValue12345678\n",
    "a/b/c/d/e/f/.env": "TOO_DEEP_TOKEN=tooDeepValue12345\n"
  });

  const found = relativeDotenvFiles(root);
  assert.deepEqual(found, ["a/b/c/d/e/.env"]);
});

test("reports what the .env cross-reference can see, so a dead layer is visible", () => {
  const populated = describeDotenvSources(makeTree({ "server/.env": "API_KEY=serverValue1234\n" }));
  assert.equal(populated.inRepo, true);
  assert.deepEqual(populated.files, ["server/.env"]);
  assert.equal(populated.secretCount, 1);

  const empty = describeDotenvSources(makeTree({ "server/index.js": "export default 1;\n" }));
  assert.equal(empty.inRepo, true);
  assert.deepEqual(empty.files, []);
  assert.equal(empty.secretCount, 0);

  // Outside a git repository there is nothing to describe.
  assert.deepEqual(describeDotenvSources(null), { inRepo: false, root: null, files: [], secretCount: 0 });
});

test("decodes UTF-16/BOM blobs so Windows/PowerShell files are scanned", () => {
  const secret = "password=SuperSecretValue123";
  const utf16le = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`${secret}\n`, "utf16le")]);
  assert.equal(decodeBlob(utf16le).includes(secret), true);
  // A real secret in a UTF-16 file must be detected once decoded.
  assert.ok(scanText("config.txt", decodeBlob(utf16le), { runGitleaks: false }).some((f) => f.ruleId === "generic-secret-assignment"));
  // UTF-8 with BOM and plain UTF-8 both round-trip.
  assert.equal(decodeBlob(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(secret)])), secret);
  assert.equal(decodeBlob(Buffer.from(secret)), secret);
});

test("does not flag trivial non-secret values (PASS=123)", () => {
  assert.equal(ruleIds("config.txt", "PASS=123").length, 0);
  assert.equal(ruleIds("config.txt", "PORT=3000").length, 0);
  assert.equal(ruleIds("config.txt", "DEBUG=true").length, 0);
});

test("shannon entropy scores random strings above plain text", () => {
  assert.ok(shannonEntropy("Zx9Kq2mVbN7pLwR4tYaSdFgHjKl") > 4.2);
  assert.ok(shannonEntropy("aaaaaaaaaaaaaaaaaaaa") < 1);
});

test("issue #44: a normal git-show exit (not staged / submodule) is the only case treated as nothing-to-scan", () => {
  // Empirically verified against real git: `git show :path` for a path that
  // is not staged, and for a submodule/gitlink entry, both exit with a
  // normal (non-zero) process status of 128 - no signal, no spawn-level
  // error code.
  assert.equal(isExpectedGitReadFailure({ status: 128 }), true);
  assert.equal(isExpectedGitReadFailure({ status: 1 }), true);
});

test("issue #44: a genuine read failure (buffer overflow, spawn failure) is not mistaken for nothing-to-scan", () => {
  // Empirically verified: when execFileSync's maxBuffer is exceeded, the
  // child is killed by a signal and the thrown error has `status: null`
  // with `code: 'ENOBUFS'` - not a normal process exit at all.
  assert.equal(isExpectedGitReadFailure({ status: null, code: "ENOBUFS", signal: "SIGTERM" }), false);
  // A spawn-level failure (missing binary, permissions) never reaches a
  // process exit either.
  assert.equal(isExpectedGitReadFailure({ status: undefined, code: "ENOENT" }), false);
  assert.equal(isExpectedGitReadFailure(new Error("boom")), false);
});

// Materializes { "relative/path": "content" } under a fresh temp directory and
// returns its root, for the .env discovery tests.
function makeTree(files) {
  const root = mkdtempSync(join(tmpdir(), "gforge-dotenv-"));
  for (const [path, content] of Object.entries(files)) {
    const full = join(root, path);
    mkdirSync(join(full, ".."), { recursive: true });
    writeFileSync(full, content);
  }
  return root;
}

function relativeDotenvFiles(root) {
  return collectDotenvFiles(root)
    .map((file) => relative(root, file).split(/[\\/]/).join("/"))
    .sort();
}
