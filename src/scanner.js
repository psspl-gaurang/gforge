
// ---------------------------------------------------------------------------
// Content that is not hand-written application code: translation catalogues,
// documentation, generated build output, and lockfiles. A credential keyword
// followed by a colon is the NORMAL shape of a translation entry
// ("Password": "Passwort") and of a docs example, so the two heuristic rules —
// generic keyword assignment and entropy — produce nothing but noise there.
//
// Only those two are suppressed. Provider rules, the secret-file rules, and the
// .env cross-reference still run on every file, so a real AWS/Stripe/GitHub
// credential committed into dist/ or a README is still blocked (issue #24).
// ---------------------------------------------------------------------------
const I18N_DIRECTORIES = new Set([
  "i18n", "l10n", "intl", "translation", "translations", "locale", "locales", "lang", "langs"
]);
const DOC_DIRECTORIES = new Set(["doc", "docs", "document", "documents", "documentation"]);
// Conventional build/vendor output. Deliberately excludes "bin" and "lib", which
// commonly hold hand-written source.
const GENERATED_DIRECTORIES = new Set([
  "dist", "build", "out", "output", "coverage", "vendor", "node_modules",
  "bower_components", "target", "obj", "__pycache__", ".next", ".nuxt", ".output",
  ".svelte-kit", ".angular", ".parcel-cache", ".turbo"
]);
// Documentation formats. `.txt` is deliberately absent — it is a common place for
// real config, and the suite relies on config.txt still being scanned.
const DOC_EXTENSIONS = new Set(["md", "mdx", "markdown", "rst", "adoc", "asciidoc"]);

export function isHeuristicExemptPath(filePath, env = process.env) {
  // Escape hatch: scan everything, exclusions off. A security tool should never
  // have a blind spot that cannot be switched back on.
  if (env && env.GFORGE_NO_DEFAULT_EXCLUDES) return null;

  const normalized = String(filePath).replace(/\\/g, "/").toLowerCase();
  const segments = normalized.split("/").filter(Boolean);
  const name = segments[segments.length - 1] ?? "";
  const directories = segments.slice(0, -1);

  if (directories.some((segment) => I18N_DIRECTORIES.has(segment))) return "i18n";
  if (directories.some((segment) => DOC_DIRECTORIES.has(segment))) return "docs";
  if (directories.some((segment) => GENERATED_DIRECTORIES.has(segment))) return "generated";

  const dot = name.lastIndexOf(".");
  const extension = dot > 0 ? name.slice(dot + 1) : "";
  if (DOC_EXTENSIONS.has(extension)) return "docs";
  if (LOCKFILE_NAMES.has(name)) return "generated";
  if (name.endsWith(".min.js") || name.endsWith(".min.css") || name.endsWith(".map")) return "generated";

  return null;
}
// GForge secret-scanning engine.
//
// This module is intentionally self-contained: it imports only Node built-ins,
// so the installer can copy it verbatim into ~/.gforge/hooks and run it as a
// pre-commit hook without depending on the globally installed package (whose
// path changes across Node/nvm versions).
//
// It never prints matched secret values — only file paths, line numbers, and
// rule identifiers.

import { execFileSync, spawn } from "node:child_process";
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Baked at install time (see getScannerContent in hooks.js). Left as a literal
// placeholder in source; only used for the update-available notice.
const RUNNING_VERSION = "__GFORGE_VERSION__";

// ---------------------------------------------------------------------------
// Provider / value-shape rules (high confidence). Ported and adapted from the
// well-known gitleaks ruleset. Each regex is matched per line.
// ---------------------------------------------------------------------------
export const PROVIDER_RULES = [
  { id: "private-key", description: "Private key block", regex: /-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY(?: BLOCK)?-----/ },
  { id: "aws-access-key-id", description: "AWS access key ID", regex: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}\b/ },
  { id: "github-pat", description: "GitHub personal access token", regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { id: "github-fine-grained-pat", description: "GitHub fine-grained token", regex: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/ },
  { id: "gitlab-pat", description: "GitLab personal access token", regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
  { id: "slack-token", description: "Slack token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: "slack-app-token", description: "Slack app token", regex: /\bxapp-[0-9]-[A-Za-z0-9-]{10,}\b/ },
  { id: "slack-webhook", description: "Slack webhook URL", regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+/ },
  { id: "stripe-secret-key", description: "Stripe secret/restricted key", regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/ },
  { id: "google-api-key", description: "Google API key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: "gcp-oauth-secret", description: "Google OAuth client secret", regex: /\bGOCSPX-[A-Za-z0-9_-]{20,}\b/ },
  // An Azure Storage account key is a 512-bit key, so its base64 form is always
  // 86 characters plus "==" padding. Anchoring on the literal AccountKey= makes
  // this effectively false-positive free (issue #28).
  {
    id: "azure-storage-key",
    description: "Azure Storage account key",
    regex: /\bAccountKey=[A-Za-z0-9+/]{86}==/
  },
  // An Entra ID (Azure AD) client secret is 40 characters from a restricted
  // alphabet and carries a "~" a few characters in. The length is matched
  // exactly, via a lookahead, because that discipline is what keeps this off
  // ordinary 40-character strings - a 40-hex SHA and a "~/..." home path both
  // stay clear (issue #28).
  {
    id: "azure-entra-client-secret",
    description: "Azure Entra ID (Azure AD) client secret",
    regex: /(?<![A-Za-z0-9._~-])(?=[A-Za-z0-9._~-]{40}(?![A-Za-z0-9._~-]))[A-Za-z0-9._-]{2,8}~[A-Za-z0-9._~-]+/
  },
  { id: "twilio-api-key", description: "Twilio API key/SID", regex: /\b(?:SK|AC)[0-9a-fA-F]{32}\b/ },
  // A Vonage/Nexmo API secret is 16 alphanumerics with no prefix - far too
  // generic to match on shape alone (a bare 16-character run occurs 130 times
  // in this repository's own source). So both alternatives anchor on something
  // Vonage-specific instead: the literal api_secret parameter, or the SDK's
  // positional (8-char key, 16-char secret) constructor. The lookbehind rather
  // than \b is deliberate, so the VONAGE_API_SECRET= env form still matches -
  // \b does not fire between an underscore and a letter (issue #28).
  {
    id: "vonage-api-secret",
    description: "Vonage/Nexmo API secret",
    regex: /(?<![A-Za-z0-9])api_secret=[A-Za-z0-9]{16}(?![A-Za-z0-9])|new\s+Vonage\s*\(\s*["'][A-Za-z0-9]{8}["']\s*,\s*["'][A-Za-z0-9]{16}["']/i
  },
  { id: "sendgrid-key", description: "SendGrid API key", regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
  { id: "mailgun-key", description: "Mailgun API key", regex: /\bkey-[0-9a-zA-Z]{32}\b/ },
  { id: "mailchimp-key", description: "Mailchimp API key", regex: /\b[0-9a-f]{32}-us[0-9]{1,2}\b/ },
  { id: "npm-token", description: "npm access token", regex: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { id: "pypi-token", description: "PyPI upload token", regex: /\bpypi-AgEIcHlwaS[A-Za-z0-9_-]{50,}\b/ },
  { id: "openai-key", description: "OpenAI API key", regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/ },
  { id: "anthropic-key", description: "Anthropic API key", regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { id: "digitalocean-token", description: "DigitalOcean token", regex: /\bdo[oprt]_v1_[a-f0-9]{64}\b/ },
  { id: "doppler-token", description: "Doppler token", regex: /\bdp\.(?:pt|st|ct|sa)\.[A-Za-z0-9]{40,}\b/ },
  { id: "shopify-token", description: "Shopify access token", regex: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/ },
  { id: "square-token", description: "Square access token", regex: /\b(?:sq0atp-[A-Za-z0-9_-]{22}|EAAA[A-Za-z0-9_-]{60})\b/ },
  { id: "telegram-bot-token", description: "Telegram bot token", regex: /\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b/ },
  { id: "jwt", description: "JSON Web Token", regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { id: "basic-auth-url", description: "Credentials embedded in URL", regex: /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s:@]{3,}@/i }
];

// Generic credential-keyword assignment (e.g. DB_PASS=..., password: "..."),
// handled specially so the assigned VALUE can be classified. A hardcoded literal
// is flagged, but a reference such as process.env.DB_PASSWORD, a function call,
// or an interpolation is NOT — blocking well-written config would defeat the
// purpose and train developers to bypass the hook.
export const GENERIC_SECRET_RULE_ID = "generic-secret-assignment";
const GENERIC_SECRET_DESCRIPTION = "hardcoded value assigned to a credential keyword";
// The keyword itself, with no boundary and no trailing context — matched
// case-insensitively, globally, so every occurrence in a line can be tried.
// Boundary and trailing-segment checks are done separately in plain JS
// below (see matchGenericKeyword), NOT as part of this pattern: character
// classes inside lookarounds are also flattened by the /i flag, so a
// lookaround here could never actually tell upper- from lowercase to detect
// a camelCase transition (verified directly against V8 before writing this).
// Order matters: unlike the original single-pattern regex (where a failed
// tail check let the engine backtrack into a later, longer alternative at
// the same position for free), matchGenericKeyword below commits to
// whichever alternative matches first and does not retry other alternatives
// at that same position. So wherever one alternative is a prefix of another
// (authorization vs. auth), the longer/more specific one must be listed
// first, or "Authorization: Bearer ..." would match only "auth" and then
// fail its own tail check instead of matching "authorization" and succeeding.
const GENERIC_KEYWORD_CORE_RE = /(?:passwd|password|passphrase|pwd|pass|secret(?:[_-]?key)?|token|access[_-]?token|authorization|auth(?:[_-]?token)?|bearer|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|private[_-]?key|encryption[_-]?key|signing[_-]?key|session[_-]?key|connection[_-]?string|conn[_-]?str|credentials?)/gi;

// At most one trailing camelCase segment right after the keyword (the
// "Value" in clientSecretValue) — deliberately not unbounded, so the match
// cannot run through an unrelated compound tail (apiSecretKeyRotationInterval)
// to reach a distant, unrelated "=".
const TRAILING_CAMEL_SEGMENT_RE = /^[A-Z][a-z0-9]*/;
// What must follow the keyword (and its optional trailing segment) for this
// to be an assignment at all, same shape the original regex required.
const KEYWORD_TAIL_RE = /^["'`]?\s*[:=]\s*(\S.*)$/;

function isAsciiUpper(ch) {
  return ch !== undefined && ch >= "A" && ch <= "Z";
}
function isAsciiLowerOrDigit(ch) {
  return ch !== undefined && ((ch >= "a" && ch <= "z") || (ch >= "0" && ch <= "9"));
}

// Finds a credential-keyword assignment anywhere in `line`, tolerating a
// camelCase compound identifier (apiSecretKey, clientSecretValue) in
// addition to the original start-of-line/non-alphanumeric-boundary forms
// (snake_case, ALL_CAPS, plain) — issue #27. Returns the captured value, or
// null. Loops past a candidate whose boundary or tail doesn't hold, rather
// than giving up after the first (leftmost) keyword-shaped substring.
function matchGenericKeyword(line) {
  GENERIC_KEYWORD_CORE_RE.lastIndex = 0;
  let found;
  while ((found = GENERIC_KEYWORD_CORE_RE.exec(line))) {
    const start = found.index;
    const end = start + found[0].length;

    const before = line[start - 1];
    const boundaryOk =
      start === 0 ||
      !/[A-Za-z0-9]/.test(before) ||
      (isAsciiLowerOrDigit(before) && isAsciiUpper(line[start]));
    if (!boundaryOk) continue;

    const rest = line.slice(end);
    const segment = rest.match(TRAILING_CAMEL_SEGMENT_RE);
    const afterKeyword = segment ? rest.slice(segment[0].length) : rest;

    const tail = afterKeyword.match(KEYWORD_TAIL_RE);
    if (tail) return tail[1];
  }
  return null;
}
// Placeholder shapes shared by the generic rule and the .env cross-reference.
// These two lists had drifted: the dotenv layer knew `your_db_password` was a
// placeholder while the generic rule did not, so every `KEY=your_*` line in a
// committed template was reported as a hardcoded credential. Defining the shared
// core once means they cannot drift again (issue #25).
const PLACEHOLDER_ALTERNATIVES = [
  "your[_-].*", // your_db_password, your-api-key
  "my[_-].*", // my_secret_value
  ".*[_-]here", // replace_me_here, your_key_here
  "changeme", "change[_-]?me", "example", "placeholder", "redacted", "dummy",
  "sample", "todo", "tbd", "xxx+"
].join("|");

const VALUE_PLACEHOLDER_RE = new RegExp(
  `^(?:${PLACEHOLDER_ALTERNATIVES}|your|my|the|test|none|null|nil|undefined|true|false|x{3,}|\\*+|password|passwd|secret|token|value|string|auth|authorization|key|apikey|api[_-]?key|credentials?)$`,
  "i"
);
const VALUE_REFERENCE_ROOT_RE = /^(process|import|globalThis|window|os|System|Deno|ENV|env|config|configService|vault|secret|secrets|settings)$/i;
// A letter that is not Latin script. Translated UI labels are written in the
// target language ("Password": "पासवर्ड"), and no credential is ever spelled in
// Devanagari, CJK, Cyrillic, Arabic, … — so this is a safe, unambiguous signal
// for translation catalogues that sit outside a recognised i18n path (issue #24).
const NON_LATIN_LETTER_RE = /[^\P{L}\p{Script=Latin}]/u;
// An Authorization value names its scheme before the credential ("Bearer <jwt>",
// "Basic <base64>"). The scheme is a label, so judge what FOLLOWS it: a real
// token after it must still flag, a bare scheme name must not (issue #23).
const AUTH_SCHEME_PREFIX_RE = /^(?:bearer|basic|digest|negotiate|oauth|jwt|token|apikey|api[_-]?key)\b[\s:]*/i;
// Expression punctuation cannot begin a credential literal. Catches the wreckage
// left when a keyword sat inside a string literal and the capture therefore
// starts at a stray quote (issue #23).
const VALUE_FRAGMENT_START_RE = /^[,;:)\]}?]/;

// A route/path template ("changepassword/:uuid") is a placeholder, not a value.
// Every segment must be a plain lowercase word or a :param — one mixed-case or
// random-looking segment means the path carries a real token and stays eligible,
// so a secret appended to a route prefix is still caught (issue #23).
const ROUTE_SEGMENT_RE = /^[a-z][a-z0-9-]*$/;
const ROUTE_SEGMENT_MAX_LENGTH = 20; // real route words; secrets run longer
// Below IDENTIFIER_MIN_VOWEL_RATIO because compound route words are vowel-poor
// ("changepassword" is 0.286), while random lowercase letters sit near 0.19.
const ROUTE_MIN_VOWEL_RATIO = 0.25;
// The route layer needs its own floor rather than NAME_SEGMENT_MIN_CHECK_LENGTH
// (8), which was picked for the entropy layer's path segments. Real route
// vocabulary is vowel-poorer than the ratio admits at short lengths —
// "graphqlws" is 0.111, "transcript" and "postgresql" 0.200, "playlists" and
// "callbacks" 0.222 — so a 475-word route corpus lost 13 words to the gate.
// Lowering the ratio is the wrong lever: over random lowercase segments placed
// after a route prefix, 0.20 drops detection at every length (66% -> 45% at 20
// characters) and STILL rejects "graphqlws"; so does a minimum-vowel-count rule.
// Raising the floor to 12 clears 12 of the 13 words and leaves detection for
// 12+ character segments exactly where it was (58-77%). What it gives up is an
// all-lowercase 8-11 character secret inside a route template, where the ratio
// was near a coin flip (52-76%) anyway (issue #68).
const ROUTE_SEGMENT_MIN_CHECK_LENGTH = 12;

// A long run of consecutive consonant LETTERS with no vowel/digit/hyphen to
// break it up is a sharper signal than vowel ratio alone, which a sizeable
// fraction of random lowercase strings satisfy purely by chance (issue #45).
//
// The threshold has to clear real route words, and 6-runs are NOT rare among
// them: "encrypt", "xmlrpc", "rhythm", "nightschool" and "graphqlws" all score
// exactly 6. Note "y" is not counted as a vowel here (encrypt -> n-c-r-y-p-t),
// but adding it would not help — xmlrpc and graphqlws contain no "y" and still
// score 6. So the bar is 7+, measured against a 290-word corpus of real route
// segments: rejecting 7+ breaks NONE of them, while rejecting 6+ breaks four
// that previously passed. Detection still improves substantially over having no
// consonant check at all (~79% vs ~66% of random 20-char lowercase segments
// caught by the segment check overall), and a genuine random secret long
// enough to matter usually clears 7 (~70% at 20 characters).
const ROUTE_MAX_CONSONANT_RUN = 6;
function maxConsonantRun(word) {
  let max = 0;
  let run = 0;
  for (const ch of word) {
    if (ch >= "a" && ch <= "z" && !"aeiou".includes(ch)) {
      run += 1;
      if (run > max) max = run;
    } else {
      run = 0;
    }
  }
  return max;
}

// A route segment is a WORD, not a blob. Lowercase is not enough on its own: hex
// beginning a-f ("a3f9b2c8…") and an all-lowercase token are lowercase too, and
// entropy cannot separate them (24 random lowercase letters score under the 4.2
// gate). Length, digit density, consonant runs, and vowel ratio can — so a
// secret cannot ride into the allowlist behind a route prefix. The consonant-run
// check applies even to short segments below the length gate: a genuinely
// short secret is unlikely, but "shorter means automatically route-shaped,
// no content check at all" is still a real gap otherwise (issue #45).
function looksLikeRouteSegment(segment) {
  const word = segment.replace(/^:/, "");
  if (!ROUTE_SEGMENT_RE.test(word)) return false;
  if (word.length > ROUTE_SEGMENT_MAX_LENGTH) return false;
  const digits = (word.match(/[0-9]/g) || []).length;
  if (digits > PATH_SEGMENT_MAX_DIGITS && digits / word.length > PATH_SEGMENT_MAX_DIGIT_RATIO) return false;
  if (maxConsonantRun(word) > ROUTE_MAX_CONSONANT_RUN) return false;
  if (word.length < ROUTE_SEGMENT_MIN_CHECK_LENGTH) return true; // api, v1, graphqlws
  const letters = word.replace(/[^a-z]/g, "");
  return letters.length > 0 && ratioOf(letters, /[aeiou]/g) >= ROUTE_MIN_VOWEL_RATIO;
}
function looksLikeRouteTemplate(value) {
  if (!/[/]:[A-Za-z_]/.test(value)) return false;
  return value.split("/").filter(Boolean).every(looksLikeRouteSegment);
}

// A constant whose value merely restates its own name is a label, not a
// credential: CALL_HISTORY_..._SESSION_KEY = "call-history-skip-default-filters".
// Only the "value is spelled out inside the key" direction counts — a random
// secret cannot appear inside the identifier that names it, whereas the reverse
// would suppress a real one (AUTH = "s3cr3tAuthValue123") (issue #23).
const KEY_IDENTIFIER_RE = /([A-Za-z_][\w.$-]*)\s*["'`]?\s*[:=]\s*$/;

// A genuine self-referential label restates its own name as a plain,
// human-readable word or slug (SESSION_KEY = "session-key"). That must not be
// confused with a real secret that merely happens to be substring-contained
// in a longer identifier which *also* carries the very credential keyword
// that triggered this rule in the first place — db_password_hunter2Real9 =
// "hunter2!Real9" is not a label restating its name, it is the same secret
// one rename away from invisibility, for a secret of any length (issue #37).
// A hand-written label never carries digits or symbol characters; a real
// generated secret almost always does — so the substring match alone is not
// enough, the value itself must still look like a plain word/slug.
const SELF_LABEL_RE = /^[A-Za-z][A-Za-z_-]*$/;
const SELF_LABEL_MIN_VOWEL_RATIO = 0.3;
function looksLikeSelfDescriptiveLabel(value) {
  if (!SELF_LABEL_RE.test(value)) return false;
  const letters = value.replace(/[^A-Za-z]/g, "");
  if (letters.length < 4) return false;
  return ratioOf(letters, /[aeiou]/gi) >= SELF_LABEL_MIN_VOWEL_RATIO;
}

function echoesItsKey(value, keyContext) {
  if (!keyContext) return false;
  const key = keyContext.match(KEY_IDENTIFIER_RE);
  if (!key) return false;
  const flatten = (text) => text.toLowerCase().replace(/[^a-z0-9]/g, "");
  const flatValue = flatten(value);
  if (flatValue.length < 4 || !flatten(key[1]).includes(flatValue)) return false;
  return looksLikeSelfDescriptiveLabel(value);
}

// Decide whether the value assigned to a credential keyword is a hardcoded
// literal (flag) rather than a reference/placeholder (ignore).
export function looksLikeHardcodedSecret(rawValue, options = {}) {
  let value = String(rawValue).trim();
  // A language string-prefix (Python f/r/b/u and combinations) directly before a
  // quote: strip it so the quote is recognized, e.g. f"Bearer {token}", rb'...'.
  value = value.replace(/^(?:[fFrRbBuU]{1,2})(?=["'`])/, "");
  const quote = value[0];
  const quoted = quote === '"' || quote === "'" || quote === "`";
  if (quoted) {
    const end = value.indexOf(quote, 1);
    // No closing quote: this quote CLOSES a string the keyword sat inside, so the
    // ':' was prose, not an assignment operator. A real `password = "…` without a
    // closing quote is a syntax error, whereas
    // `console.error('failed to clear auth:', err)` is everyday code (issue #23).
    if (end === -1) return false;
    value = value.slice(1, end);
  }
  // Drop the scheme label so the credential itself is judged.
  value = value.replace(AUTH_SCHEME_PREFIX_RE, "").trim();
  if (!quoted) {
    // Unquoted: the value ends at the first separator. A trailing quote closes the
    // string this value was embedded in (-H "Authorization: Bearer TOKEN").
    value = value.split(/[\s,;)}\]]/)[0].replace(/["'`]+$/, "");
  }
  value = value.trim();

  if (value.length < 4) return false;
  // An expression fragment, not a literal.
  if (VALUE_FRAGMENT_START_RE.test(value)) return false;
  // Interpolations / template placeholders are references, not literals:
  // ${...}, {{...}}, %(...)s, <%...%>, #{...}, and single-brace {ident} used by
  // Python f-strings and C# interpolated strings (e.g. `Bearer {token}`).
  if (/\$\{|\{\{|%\(|<%|#\{|\{[A-Za-z_][\w.]*\}/.test(value)) return false;
  if (looksLikeRouteTemplate(value)) return false;
  if (!quoted) {
    // Unquoted expressions: shell vars, member access, function calls, env lookups.
    if (value.startsWith("$")) return false;
    if (/[.(]/.test(value)) return false;
    if (VALUE_REFERENCE_ROOT_RE.test(value)) return false;
    // In source code, an unquoted bare identifier (user.password = hashedPassword)
    // is a variable reference, not a literal. In config/env/YAML files an unquoted
    // bare word IS the literal value, so only exempt this for code files.
    if (options.codeFile && /^[A-Za-z_$][\w$]*$/.test(value)) return false;
  }
  // A translated label, not a credential. Narrow on purpose: the value must be
  // PURE non-Latin text (no ASCII letters or digits) and must sit in a data file,
  // so a human-chosen password in application code — password = "пароль123", or
  // even bare "пароль" — is still flagged.
  if (!options.codeFile && NON_LATIN_LETTER_RE.test(value) && !/[A-Za-z0-9]/.test(value)) return false;
  // Env-name-like placeholders (DB_PASSWORD) and common dummy values.
  if (/^[A-Z][A-Z0-9_]{2,}$/.test(value)) return false;
  if (VALUE_PLACEHOLDER_RE.test(value)) return false;
  if (echoesItsKey(value, options.keyContext)) return false;
  if (/^<.*>$/.test(value) || value === "...") return false;

  return true;
}

// Known source-code file types, where unquoted bare identifiers are variable
// references. Anything else (.env, .yml, .ini, .properties, .txt, …) is treated
// as a config/literal file.
const CODE_EXTENSIONS = new Set([
  "js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "rb", "go", "java", "kt", "kts",
  "php", "cs", "cpp", "cc", "cxx", "c", "h", "hpp", "rs", "swift", "scala", "dart",
  "lua", "pl", "pm", "r", "mm", "vue", "svelte", "groovy", "clj", "ex", "exs"
]);

function isCodeFile(filePath) {
  const name = basename(filePath).toLowerCase();
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return false;
  return CODE_EXTENSIONS.has(name.slice(dot + 1));
}

// ---------------------------------------------------------------------------
// Secret-file rules: files that should essentially never be committed. Matched
// against the file's basename (and a couple of path suffixes).
// ---------------------------------------------------------------------------
const ALLOWED_ENV_SUFFIXES = new Set(["example", "sample", "template", "dist", "defaults", "tpl", "test"]);

// The final dot-segment of a `.env.*` basename, or "" if this is not one.
// Templates are routinely named descriptively — `.env.cron-cdr-backfill.example`,
// `.env.local.example`, `.env.staging.template` — so only the LAST segment can
// decide. Comparing the whole remainder after ".env." treated every such file as
// a real env file: a `secret-file-env` finding plus a full content scan of what
// is, by definition, placeholders (issue #25).
function envSuffix(filePath) {
  const name = basename(filePath).toLowerCase();
  if (!name.startsWith(".env.")) return "";
  const rest = name.slice(".env.".length);
  const lastDot = rest.lastIndexOf(".");
  return lastDot === -1 ? rest : rest.slice(lastDot + 1);
}

// True for env template files (.env.example, .env.sample, ...) that are meant
// to be committed with placeholder values.
export function isEnvTemplate(filePath) {
  return ALLOWED_ENV_SUFFIXES.has(envSuffix(filePath));
}

export function matchFilenameRule(filePath) {
  const name = basename(filePath).toLowerCase();

  // Environment files, except obvious templates (.env.example, .env.sample, ...).
  if (name === ".env") {
    return { id: "secret-file-env", description: ".env file (may contain secrets)" };
  }
  if (name.startsWith(".env.") && !isEnvTemplate(filePath)) {
    return { id: "secret-file-env", description: "environment file (may contain secrets)" };
  }

  // Private key material and credential stores.
  const exactNames = new Set([
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".git-credentials", ".htpasswd", ".pgpass", ".netrc",
    "credentials"
  ]);
  if (exactNames.has(name)) {
    return { id: "secret-file", description: "credential/private-key file" };
  }

  const secretExtensions = [".p12", ".pfx", ".pkcs12", ".keystore", ".jks", ".ppk", ".kdbx"];
  if (secretExtensions.some((ext) => name.endsWith(ext))) {
    return { id: "secret-file", description: "keystore/credential file" };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Entropy detection for high-entropy strings that carry no recognizable name.
// ---------------------------------------------------------------------------
const ENTROPY_MIN_LENGTH = 20;
const ENTROPY_THRESHOLD = 4.2; // pure hex/decimal/UUID cannot reach this; base64-like secrets do.
const ENTROPY_TOKEN = /[A-Za-z0-9+/=_-]{20,}/g;
// A path segment is identifier-shaped: optionally dot-prefixed, letter-initial,
// and carrying few digits. Random base64 segments fail on digit density.
const PATH_SEGMENT = /^\.?[A-Za-z][A-Za-z0-9_.-]*$/;
const PATH_SEGMENT_MAX_DIGITS = 2;
const PATH_SEGMENT_MAX_DIGIT_RATIO = 0.15;
const IDENTIFIER_MIN_VOWEL_RATIO = 0.3; // English words ~40% vowels; random secrets ~16%
const NAME_SEGMENT_MIN_CHECK_LENGTH = 8; // shorter path segments (src, api, v2) can't be secrets
const LOCKFILE_NAMES = new Set([
  "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
  "composer.lock", "gemfile.lock", "go.sum", "cargo.lock", "poetry.lock",
  "podfile.lock", "flake.lock"
]);

export function shannonEntropy(str) {
  if (!str) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function ratioOf(str, pattern) {
  if (!str) return 0;
  return (str.match(pattern) || []).length / str.length;
}

function isPathSegment(segment) {
  if (!PATH_SEGMENT.test(segment)) return false;
  const digits = (segment.match(/[0-9]/g) || []).length;
  return digits <= PATH_SEGMENT_MAX_DIGITS || digits / segment.length <= PATH_SEGMENT_MAX_DIGIT_RATIO;
}

// A segment that reads as a name, not random base64. It must be identifier-shaped
// with few digits (isPathSegment); then a short segment (src, api, v2, js) can
// never be a meaningful secret, a SCREAMING_SNAKE_CASE word (BACKEND_DIR) is a
// clean const/env name, and any longer segment must be vowel-rich like a real
// word. Random base64 segments are long, ~19% vowels, and mixed-case, so they
// fail every branch (see issue #19).
function looksLikeNameSegment(segment) {
  if (!isPathSegment(segment)) return false;
  if (segment.length < NAME_SEGMENT_MIN_CHECK_LENGTH) return true;
  if (/^[A-Z][A-Z0-9_]*$/.test(segment)) return true;
  const letters = segment.replace(/[^A-Za-z]/g, "");
  return letters.length > 0 && ratioOf(letters, /[aeiouAEIOU]/g) >= IDENTIFIER_MIN_VOWEL_RATIO;
}

// `/` belongs in ENTROPY_TOKEN because base64 secrets use it — but that also
// makes an entire import path one token, and the concatenation scores far above
// the bare name (`src/components/GlobalFilterSidebar/GlobalFilterSummaryTrigger`
// is 4.229; `GlobalFilterSummaryTrigger` alone is 3.825). So a path is scored
// per segment instead of whole.
//
// The gate is the load-bearing part. Splitting *every* token on `/` costs real
// detection, because standard base64 uses `/` as an alphabet character: over
// random 40-char AWS secret access keys, unconditional splitting drops
// detection to ~86%. Requiring identifier-shaped segments plus a
// lowercase-heavy token holds that at ~99.8%, since random base64 is only ~40%
// lowercase and its segments carry ~25% digits.
//
// Deliberately splits on `/` only. `-` and `_` are the base64url alphabet, so
// splitting on them too would cut detection of a token embedded in a URL path
// (e.g. `/auth/reset/<base64url>`) from 100% to ~95%.
function looksLikePath(token) {
  if (!token.includes("/")) return false;
  const segments = token.split("/").filter(Boolean);
  if (segments.length < 2) return false;
  // Every segment must read as a name (word or SCREAMING_SNAKE), not base64. This
  // replaces the whole-token lowercase-ratio gate, which mis-rejected paths that
  // contain an all-caps segment such as $BACKEND_DIR/requirements (issue #19).
  return segments.every(looksLikeNameSegment);
}

// The strings actually scored for one matched token: a path's segments, or the
// token itself.
export function entropyCandidates(token) {
  return looksLikePath(token) ? token.split("/").filter(Boolean) : [token];
}

// A plain identifier (camelCase / PascalCase / snake_case): identifier characters
// only - no base64/base64url symbols (+ / = -) - with few digits and a
// vowel-rich body. English-word names like `buildBookingMatchWhereClause` clear
// 4.2 bits of entropy but are ~40% vowels; random base64/hex secrets are ~16%
// vowels and digit-heavy, so they fail the vowel or the digit gate. Excluding
// identifiers keeps ~96-99% of random-secret detection (see issue #17).
export function looksLikeIdentifier(token) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(token)) return false;
  const digits = (token.match(/[0-9]/g) || []).length;
  const fewDigits = digits <= PATH_SEGMENT_MAX_DIGITS || digits / token.length <= PATH_SEGMENT_MAX_DIGIT_RATIO;
  const vowels = (token.match(/[aeiouAEIOU]/g) || []).length;
  return fewDigits && vowels / token.length >= IDENTIFIER_MIN_VOWEL_RATIO;
}

function hasHighEntropyToken(line) {
  const tokens = line.match(ENTROPY_TOKEN);
  if (!tokens) return false;
  for (const token of tokens) {
    for (const candidate of entropyCandidates(token)) {
      if (candidate.length < ENTROPY_MIN_LENGTH) continue;
      if (looksLikeIdentifier(candidate)) continue; // natural identifier name, not a secret
      if (shannonEntropy(candidate) >= ENTROPY_THRESHOLD) return true;
    }
  }
  return false;
}

function looksBinary(content) {
  const sample = content.slice(0, 8000);
  let control = 0;
  for (let i = 0; i < sample.length; i += 1) {
    const code = sample.charCodeAt(i);
    if (code === 0) return true;
    if (code < 9 || (code > 13 && code < 32)) control += 1;
  }
  return control / (sample.length || 1) > 0.3;
}

// ---------------------------------------------------------------------------
// Allowlist: a .gforgeignore (or .gitleaksignore) file whose non-comment lines
// are path substrings/regexes to skip, plus inline `gforge:allow` comments.
// ---------------------------------------------------------------------------
const INLINE_ALLOW = /(?:gforge|gitleaks):allow/i;

// Allowlist entries are repo-controlled and compiled into regexes that run
// against every staged path on every commit. A pattern with nested unbounded
// quantifiers backtracks catastrophically: `(a+)+$` against a 31-character
// path did not finish in 12 seconds here, which hangs the commit hook outright
// (issue #31).
//
// A clone of an untrusted repository inherits its .gforgeignore silently, so
// the trust assumption is worth enforcing rather than documenting alone.
const ALLOWLIST_MAX_PATTERN_LENGTH = 200;
// A group that already contains an unbounded quantifier, itself quantified:
// (a+)+ (a*)* (a+)* (a*)+ (a+){2,} and so on. Conservative on purpose - real
// allowlist entries look like `test/fixtures/` or `^docs/sample\.md$`, and
// none of those come close to this shape.
const NESTED_QUANTIFIER_RE = /\([^)]*[+*][^)]*\)\s*(?:[+*]|\{\d+,\s*\})/;

export function isRiskyAllowlistPattern(line) {
  const value = String(line ?? "");
  if (value.length > ALLOWLIST_MAX_PATTERN_LENGTH) return true;
  return NESTED_QUANTIFIER_RE.test(value);
}

export function parseAllowlist(text) {
  if (!text) return [];
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => {
      // Falls through to the literal matcher below, which is the same
      // treatment an uncompilable regex already got. The entry stops matching
      // as a pattern, which fails SAFE: the path is scanned rather than
      // skipped, so a hostile or broken entry can never hide a file.
      if (!isRiskyAllowlistPattern(line)) {
        try {
          return new RegExp(line);
        } catch {
          // Not a valid regex: treat as a literal path substring.
        }
      }
      return { test: (value) => value.includes(line) };
    });
}

function isPathAllowlisted(filePath, allowlist) {
  return allowlist.some((matcher) => matcher.test(filePath));
}

// ---------------------------------------------------------------------------
// Core text scanner.
// ---------------------------------------------------------------------------
export function scanText(filePath, content, options = {}) {
  const findings = [];
  const name = basename(filePath).toLowerCase();
  // Translation catalogues, docs, build output and lockfiles: suppress the two
  // heuristic rules, never the high-confidence ones (issue #24).
  const exemptReason = isHeuristicExemptPath(filePath);
  const skipEntropy = options.entropy === false || Boolean(exemptReason) || looksBinary(content);

  const includeGeneric = options.generic !== false && !exemptReason;
  const codeFile = isCodeFile(filePath);
  // Twilio auth tokens are bare 32-hex strings (no prefix), indistinguishable
  // from an MD5 on their own. Only treat a 32-hex string as a token when the
  // file also carries Twilio context (an AC…/SK… SID or the word "twilio").
  const twilioContext = /twilio/i.test(content) || /\b(?:AC|SK)[0-9a-fA-F]{32}\b/.test(content);
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (INLINE_ALLOW.test(line)) continue;
    const lineNumber = i + 1;

    for (const rule of PROVIDER_RULES) {
      if (rule.regex.test(line)) {
        findings.push({ file: filePath, line: lineNumber, ruleId: rule.id, description: rule.description });
      }
    }

    if (twilioContext && /(?<![A-Za-z0-9])[0-9a-fA-F]{32}(?![A-Za-z0-9])/.test(line)) {
      findings.push({
        file: filePath,
        line: lineNumber,
        ruleId: "twilio-auth-token",
        description: "possible Twilio auth token (32-hex value in a Twilio context)"
      });
    }

    if (includeGeneric) {
      const value = matchGenericKeyword(line);
      // Everything left of the value: the capture runs to end of line, so the
      // remainder names the key the value was assigned to.
      const keyContext = value !== null ? line.slice(0, line.length - value.length) : "";
      if (value !== null && looksLikeHardcodedSecret(value, { codeFile, keyContext })) {
        findings.push({
          file: filePath,
          line: lineNumber,
          ruleId: GENERIC_SECRET_RULE_ID,
          description: GENERIC_SECRET_DESCRIPTION
        });
      }
    }

    // One entropy finding per line is enough.
    if (!skipEntropy && hasHighEntropyToken(line)) {
      findings.push({
        file: filePath,
        line: lineNumber,
        ruleId: "high-entropy-string",
        description: "high-entropy string with no recognizable name"
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Git integration.
// ---------------------------------------------------------------------------
function git(args, options = {}) {
  // Capture stdout; silence stderr so expected failures (e.g. `git show` for a
  // path that is not staged) do not spew "fatal:" noise on every commit.
  return execFileSync("git", args, {
    maxBuffer: 1024 * 1024 * 512,
    stdio: ["ignore", "pipe", "ignore"],
    ...options
  });
}

export const STAGED_DIFF_FILTER = "ACMRT";

function stagedFiles() {
  // -z emits raw NUL-delimited paths (no quoting/escaping), so no core.quotePath needed.
  //
  // T (type-changed) matters as much as the rest: replacing a tracked symlink
  // with a regular file leaves the new content fully staged, but git reports it
  // as T, so leaving T out of the filter made that file invisible to every rule
  // - a complete bypass of the scanner, not a weakened one (issue #80).
  //
  // D is still excluded because a deletion stages no content to scan, and U
  // (unmerged) because git refuses to commit a conflicted path in the first
  // place, so the hook never has to judge one.
  const out = git(["diff", "--cached", "-z", "--name-only", `--diff-filter=${STAGED_DIFF_FILTER}`]);
  return out.toString("utf8").split("\0").filter(Boolean);
}

// Decode a git blob to text, honoring BOMs and BOM-less UTF-16 (common on
// Windows, e.g. files written by PowerShell's `>`/Out-File). Without this a
// UTF-16 secret reads as interleaved NUL bytes and no rule matches. Falls back
// to latin1 so binary content is still scanned byte-for-byte.
export function decodeBlob(buf) {
  if (!buf || buf.length === 0) return "";
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return buf.toString("utf16le", 2);
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    const swapped = Buffer.from(buf.subarray(2));
    swapped.swap16();
    return swapped.toString("utf16le");
  }
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    return buf.toString("utf8", 3);
  }
  // BOM-less UTF-16LE heuristic: many NULs in the odd byte positions.
  const sample = Math.min(buf.length, 1024);
  if (sample >= 4) {
    let zeros = 0;
    let checked = 0;
    for (let i = 1; i < sample; i += 2) {
      checked += 1;
      if (buf[i] === 0) zeros += 1;
    }
    if (checked > 0 && zeros / checked > 0.7) return buf.toString("utf16le");
  }
  return buf.toString("latin1");
}

// `git show :path` exits with a normal (non-zero) process status for the two
// genuinely expected failures — the path is not staged, or it is a
// submodule/gitlink entry — so `error.status` is a real exit code in both
// cases (verified empirically: 128 for each). Anything else — the process
// killed by a signal (maxBuffer exceeded leaves `status: null`), a spawn
// failure (missing binary, permissions) — is a real read failure, not
// "nothing to scan here", and must not be treated the same way (issue #44).
export function isExpectedGitReadFailure(error) {
  return typeof error?.status === "number";
}

function stagedContent(filePath) {
  try {
    return decodeBlob(git(["show", `:${filePath}`]));
  } catch (error) {
    if (isExpectedGitReadFailure(error)) return null; // submodule/gitlink or not staged.
    throw error; // genuine read failure: fail closed rather than scan nothing.
  }
}

// The working-tree root, or null when not inside a git repository.
function repoRoot() {
  try {
    return git(["rev-parse", "--show-toplevel"]).toString("utf8").trim() || null;
  } catch {
    return null;
  }
}

function loadAllowlist() {
  const root = repoRoot();
  if (!root) return [];
  const patterns = [];
  for (const file of [".gforgeignore", ".gitleaksignore"]) {
    const content = stagedOrWorkingFile(root, file);
    if (content) patterns.push(...parseAllowlist(content));
  }
  return patterns;
}

function stagedOrWorkingFile(root, relPath) {
  // Prefer the staged version, fall back to the working tree.
  const staged = stagedContent(relPath);
  if (staged !== null) return staged;
  try {
    return readFileSync(`${root}/${relPath}`, "utf8");
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// .env cross-reference: the highest-precision signal. Collect the actual secret
// VALUES from the repo's (git-ignored) .env files, then flag any staged file
// that hardcodes one of those values verbatim — the classic "copied the token
// out of .env into the code" leak. Values are never printed.
//
// Env files live next to the package that owns them. A monorepo keeps them in
// subdirectories (server/.env, client/.env, ...) and frequently has no root
// .env at all, so reading a fixed list of filenames in the repo root loaded
// zero secrets and silently disabled this whole layer (issue #26). The repo is
// walked instead, bounded by depth, directory budget and the generated/vendor
// skip list so a large tree cannot slow a commit down.
// ---------------------------------------------------------------------------
const DOTENV_MAX_DEPTH = 5;
// Reached only by a repo with thousands of non-vendored directories; a tree
// that large costs a few hundred ms to walk, and a normal one a few tens.
const DOTENV_MAX_DIRECTORIES = 4000;
const DOTENV_MAX_BYTES = 1024 * 1024;
// Build output, vendored dependencies and virtualenvs hold other projects'
// env files, not this repo's — and are where the file count explodes.
const DOTENV_SKIP_DIRECTORIES = new Set([
  ...GENERATED_DIRECTORIES, ".git", ".hg", ".svn", ".venv", "venv", "virtualenv",
  ".tox", ".gradle", ".terraform", ".cache", ".yarn", ".pnpm-store", "pods"
]);
const DOTENV_KEY_IS_SECRET = /(pass|pwd|secret|token|key|auth|cred|api|private|access|signature|salt)/i;
// Shares PLACEHOLDER_ALTERNATIVES with the generic rule (see issue #25); the
// extras here are environment-ish values that are real but not secret.
const DOTENV_VALUE_STOPLIST = new RegExp(
  `^(?:${PLACEHOLDER_ALTERNATIVES}|true|false|null|none|undefined|localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|development|production|staging|test)$`,
  "i"
);

// A weak/common dev-default value ("password") sitting behind a
// credential-shaped key name used to be trusted unconditionally — but it
// gets cross-referenced against every staged file as an exact string, so a
// short, common word is exactly the value most likely to also appear,
// completely unrelated, as plain text elsewhere (a `type="password"` HTML
// attribute) (issue #43). Real generated secrets/tokens run far longer than
// this in practice, so require some real length even once the key matches.
const DOTENV_MIN_KEYED_VALUE_LENGTH = 10;
// A CSS-shaped hex color (#fff, #a1b2c3, #a1b2c3d4) — a very common `.env`
// theme/branding value, and its short, fixed-alphabet shape is exactly what
// makes it likely to coincidentally match unrelated code (issue #43).
const DOTENV_HEX_COLOR_RE = /^#?[0-9a-fA-F]{3,4}$|^#?[0-9a-fA-F]{6}$|^#?[0-9a-fA-F]{8}$/;

function looksLikeDotenvSecret(key, value) {
  if (value.length < 6) return false;
  if (DOTENV_VALUE_STOPLIST.test(value)) return false;
  if (/^\d+$/.test(value)) return false; // ports, ids
  if (DOTENV_HEX_COLOR_RE.test(value)) return false;
  if (DOTENV_KEY_IS_SECRET.test(key)) return value.length >= DOTENV_MIN_KEYED_VALUE_LENGTH;
  // Otherwise only treat long, random-looking values as secrets.
  return value.length >= 12 && /[A-Za-z]/.test(value) && /[0-9]/.test(value);
}

// A real env file: `.env`, or `.env.<anything>` that is not a placeholder
// template. Templates are tracked and hold fake values, so cross-referencing
// them would block commits on the very placeholders issue #25 taught us to
// ignore.
export function isDotenvFile(filePath) {
  const name = basename(filePath).toLowerCase();
  if (name === ".env") return true;
  return name.startsWith(".env.") && !isEnvTemplate(name);
}

// Every env file in the repo. Breadth-first on purpose: env files sit at
// package roots, so if a pathological tree exhausts the directory budget it is
// the deepest directories that go unread, never a sibling package's .env.
export function collectDotenvFiles(root) {
  const found = [];
  let queue = [root];
  let depth = 0;
  let budget = DOTENV_MAX_DIRECTORIES;

  while (queue.length > 0 && budget > 0) {
    const next = [];

    for (const directory of queue) {
      if (budget <= 0) break;
      budget -= 1;

      let entries;
      try {
        entries = readdirSync(directory, { withFileTypes: true });
      } catch {
        continue; // unreadable directory (permissions, race); nothing to load here.
      }

      for (const entry of entries) {
        // Symlinks report as neither file nor directory here, which also keeps
        // the walk free of symlink loops.
        if (entry.isDirectory()) {
          if (depth >= DOTENV_MAX_DEPTH) continue;
          if (DOTENV_SKIP_DIRECTORIES.has(entry.name.toLowerCase())) continue;
          next.push(join(directory, entry.name));
        } else if (entry.isFile() && isDotenvFile(entry.name)) {
          found.push(join(directory, entry.name));
        }
      }
    }

    queue = next;
    depth += 1;
  }

  return found;
}

export function loadDotenvSecrets(root = repoRoot()) {
  return root ? dotenvSecretsFrom(collectDotenvFiles(root)) : [];
}

function dotenvSecretsFrom(files) {
  const secrets = new Set();
  for (const file of files) {
    let text;
    try {
      // An env file is a handful of lines; anything larger is not one, and
      // reading it would stall the commit.
      if (statSync(file).size > DOTENV_MAX_BYTES) continue;
      text = decodeBlob(readFileSync(file));
    } catch {
      continue;
    }
    for (const line of text.split(/\r?\n/)) {
      const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
      if (!match) continue;
      let value = match[2].trim();
      const q = value[0];
      if ((q === '"' || q === "'" || q === "`") && value.endsWith(q)) {
        value = value.slice(1, -1);
      } else {
        value = value.split(/\s+#/)[0].trim(); // drop trailing inline comment
      }
      if (looksLikeDotenvSecret(match[1], value)) secrets.add(value);
    }
  }
  return [...secrets];
}

// What the cross-reference can actually see, for `gforge verify`. A layer that
// silently loads nothing is indistinguishable from one that is working, which
// is how the monorepo gap went unnoticed (issue #26). Reports file paths and
// counts only — never a value.
export function describeDotenvSources(root = repoRoot()) {
  if (!root) return { inRepo: false, root: null, files: [], secretCount: 0 };
  const files = collectDotenvFiles(root);
  return {
    inRepo: true,
    root,
    files: files.map((file) => relative(root, file).replace(/\\/g, "/")).sort(),
    secretCount: dotenvSecretsFrom(files).length
  };
}

// Finds the first occurrence of `needle` that isn't embedded inside a larger
// run of identifier characters on either side — a short secret value must
// not match as a coincidental fragment of an unrelated, longer word/token
// (issue #43: e.g. a secret "pass" must not match inside "passenger"). A
// needle whose own edge isn't itself an identifier character (starts or ends
// with a symbol) has no boundary to violate on that side, so any occurrence
// there already counts, same as a plain substring match would.
function isIdentifierChar(ch) {
  return ch !== undefined && /[A-Za-z0-9_]/.test(ch);
}
function findWordBoundaryIndex(content, needle) {
  const needleStartsWord = isIdentifierChar(needle[0]);
  const needleEndsWord = isIdentifierChar(needle[needle.length - 1]);
  let index = content.indexOf(needle);
  while (index !== -1) {
    const leftOk = !needleStartsWord || !isIdentifierChar(content[index - 1]);
    const rightOk = !needleEndsWord || !isIdentifierChar(content[index + needle.length]);
    if (leftOk && rightOk) return index;
    index = content.indexOf(needle, index + 1);
  }
  return -1;
}

// Optional turbo layer: if the gitleaks binary is installed, run it over the
// staged changes and merge its verdict. Uses --redact so no secret is printed.
function runGitleaks() {
  try {
    execFileSync("gitleaks", ["version"], { stdio: "ignore" });
  } catch {
    return { available: false, leaks: false };
  }

  try {
    execFileSync("gitleaks", ["protect", "--staged", "--redact", "--no-banner"], { stdio: "pipe" });
    return { available: true, leaks: false };
  } catch (error) {
    if (error && error.status === 1) {
      return { available: true, leaks: true };
    }
    // Unsupported subcommand on a newer/older gitleaks, or another error:
    // do not block on gitleaks itself; the native engine still ran.
    return { available: true, leaks: false, errored: true };
  }
}

export function scanStaged(options = {}) {
  const allowlist = options.allowlist ?? loadAllowlist();
  const files = options.files ?? stagedFiles();
  const dotenvSecrets = options.dotenvSecrets ?? loadDotenvSecrets();
  const findings = [];

  for (const file of files) {
    if (isPathAllowlisted(file, allowlist)) continue;

    const fileRule = matchFilenameRule(file);
    if (fileRule) {
      findings.push({ file, line: 0, ruleId: fileRule.id, description: fileRule.description });
    }

    const content = options.read ? options.read(file) : stagedContent(file);
    if (content === null || content === undefined) continue;

    // Highest-precision check: a real secret value from .env hardcoded here.
    for (const secret of dotenvSecrets) {
      const index = findWordBoundaryIndex(content, secret);
      if (index !== -1) {
        findings.push({
          file,
          line: content.slice(0, index).split(/\r?\n/).length,
          ruleId: "hardcoded-dotenv-secret",
          description: "a secret value from a .env file is hardcoded here"
        });
        break; // one is enough to block; do not enumerate values
      }
    }

    // Env templates are meant to hold placeholder values, so skip the generic
    // keyword and entropy rules for them, but still catch a real provider token.
    const fileOptions = isEnvTemplate(file) ? { ...options, generic: false, entropy: false } : options;
    findings.push(...scanText(file, content, fileOptions));
  }

  const gitleaks = options.runGitleaks === false ? { available: false, leaks: false } : runGitleaks();
  return { findings, gitleaks };
}

// ---------------------------------------------------------------------------
// Reporting (never prints matched values). Danger-styled when the output is an
// interactive terminal; plain otherwise (pipes, CI, NO_COLOR).
// ---------------------------------------------------------------------------
function makePalette(enabled) {
  const wrap = (code) => (text) => (enabled ? `[${code}m${text}[0m` : text);
  return {
    danger: wrap("1;97;41"), // bold white on red — the banner
    red: wrap("31"),
    redBold: wrap("1;31"),
    yellow: wrap("33"),
    bold: wrap("1"),
    dim: wrap("2")
  };
}

export function colorEnabled(stream) {
  if (process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR) return true;
  return Boolean(stream && stream.isTTY);
}

export function formatReport({ findings, gitleaks }, options = {}) {
  const c = makePalette(Boolean(options.color));
  const lines = [];
  lines.push(c.danger("  ⚒  GForge - COMMIT BLOCKED  "));
  lines.push(c.redBold("Potential secrets detected in staged changes:"));
  lines.push("");

  const byFile = new Map();
  for (const f of findings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }

  for (const [file, fileFindings] of byFile) {
    lines.push(`  ${c.bold(file)}`);
    for (const f of fileFindings) {
      const where = f.line > 0 ? `line ${f.line}` : "file";
      lines.push(`    ${c.red("✗")} ${c.yellow(`[${f.ruleId}]`)} ${f.description} (${where})`);
    }
  }

  if (gitleaks?.leaks) {
    lines.push(`  ${c.yellow("(gitleaks also reported findings in the staged changes)")}`);
  }

  lines.push("");
  lines.push(c.dim("No secret values are printed above. To proceed you can:"));
  lines.push(c.dim("  - remove the secret from the staged change, or"));
  lines.push(c.dim("  - mark a false positive with an inline `gforge:allow` comment, or"));
  lines.push(c.dim("  - add a path/pattern to a .gforgeignore file, or"));
  lines.push(c.dim("  - bypass this one commit with: git commit --no-verify"));
  return `${lines.join("\n")}\n`;
}

export function runPreCommit(write = (s) => process.stderr.write(s)) {
  const result = scanStaged();
  const blocked = result.findings.length > 0 || result.gitleaks?.leaks;
  if (blocked) {
    write(formatReport(result, { color: colorEnabled(process.stderr) }));
    return 1;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Update notification (never blocks or delays the commit).
//
// The commit path only READS a cache written by a detached background check, so
// no network happens on the critical path. Once/day the hook fire-and-forgets a
// background refresh of that cache; with GFORGE_AUTO_UPDATE=1 the background
// process also upgrades the package.
// ---------------------------------------------------------------------------
const UPDATE_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const REGISTRY_URL = "https://registry.npmjs.org/gforge/latest";

function updateCachePath() {
  return join(homedir(), ".gforge", "update-check.json");
}

function versionIsNewer(latest, current) {
  const pa = String(latest).split(".").map((n) => parseInt(n, 10) || 0);
  const pb = String(current).split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i += 1) {
    if ((pa[i] || 0) > (pb[i] || 0)) return true;
    if ((pa[i] || 0) < (pb[i] || 0)) return false;
  }
  return false;
}

// Reads the cached latest version, prints a one-line notice if newer, and once a
// day fire-and-forgets a background refresh. Fully best-effort — any failure is
// swallowed so it can never affect the commit.
function maybeUpdateNotice(write) {
  try {
    let cache = null;
    try {
      cache = JSON.parse(readFileSync(updateCachePath(), "utf8"));
    } catch {
      cache = null;
    }

    if (cache && cache.latest && RUNNING_VERSION[0] !== "_" && versionIsNewer(cache.latest, RUNNING_VERSION)) {
      write(`\ngforge: v${cache.latest} is available (you have v${RUNNING_VERSION}). Run: gforge update\n`);
    }

    const stale = !cache || (Date.now() - (cache.checkedAt || 0)) > UPDATE_CACHE_TTL_MS;
    if (stale) {
      const self = fileURLToPath(import.meta.url);
      const child = spawn(process.execPath, [self, "__update-check"], {
        detached: true,
        stdio: "ignore"
      });
      child.unref();
    }
  } catch {
    // Never let update logic affect a commit.
  }
}

// Background worker: refresh the cache and (opt-in) auto-upgrade. Detached from
// the commit, so it may take its time.
async function runUpdateCheck() {
  const cachePath = updateCachePath();
  let latest = null;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6000);
    try {
      const response = await fetch(REGISTRY_URL, { signal: controller.signal });
      if (response.ok) {
        const body = await response.json();
        if (body && /^\d+\.\d+\.\d+/.test(String(body.version || ""))) latest = body.version;
      }
    } finally {
      clearTimeout(timer);
    }
  } catch {
    latest = null;
  }

  try {
    // Always stamp checkedAt so a failed check still waits a day before retrying.
    writeFileSync(cachePath, `${JSON.stringify({ checkedAt: Date.now(), latest: latest ?? null })}\n`);
  } catch {
    // ignore
  }

  // Auto-install is ON by default; opt out with GFORGE_AUTO_UPDATE=0/false/off/no.
  const optOut = ["0", "false", "off", "no"].includes(String(process.env.GFORGE_AUTO_UPDATE || "").toLowerCase());
  const safeVersion = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(String(latest || ""));
  if (latest && safeVersion && !optOut && RUNNING_VERSION[0] !== "_" && versionIsNewer(latest, RUNNING_VERSION)) {
    try {
      // Install target is the constant gforge@latest (== the version we just
      // detected); nothing registry-derived is interpolated into the command.
      const npm = spawn("npm", ["install", "-g", "gforge@latest"], {
        stdio: "ignore",
        shell: process.platform === "win32"
      });
      await new Promise((resolve) => npm.on("close", resolve).on("error", resolve));
    } catch {
      // ignore; the notice will still prompt a manual `gforge update`.
    }
  }
}

// Run as a hook when executed directly (e.g. ~/.gforge/hooks/gforge-scan.mjs).
const invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  if (process.argv[2] === "__update-check") {
    runUpdateCheck().finally(() => process.exit(0));
  } else {
    try {
      const code = runPreCommit();
      maybeUpdateNotice((s) => process.stderr.write(s));
      process.exit(code);
    } catch (error) {
      // Fail closed: if the scanner cannot run, block rather than risk a leak.
      process.stderr.write(`GForge: secret scan could not complete, blocking commit for safety.\n${error?.message ?? error}\n`);
      process.exit(1);
    }
  }
}
