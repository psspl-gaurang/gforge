// `gforge history`: scan a repository's existing commit history for secrets
// that were committed before GForge was installed - the commit hook only ever
// sees what is staged next, so anything already in history is invisible to it
// (issue #88).
//
// Every past VERSION of every file is scanned once, not every commit's whole
// tree: a blob is content-addressed, so one unchanged across a thousand
// commits is one scan. Each finding is attributed to the commit that first
// introduced that version, which is the commit that leaked it.
//
// The per-file checks are the commit hook's own (scanFileContent), so the two
// cannot disagree about what counts as a leak. Never prints a matched value.

import { spawnSync } from "node:child_process";

import {
  decodeBlob,
  isPathAllowlisted,
  loadAllowlist,
  loadCustomRules,
  loadDotenvSecrets,
  scanFileContent
} from "./scanner.js";

// Larger versions are reported by name rather than scanned, so a vendored
// dump or binary cannot make the scan unbounded - and nothing is skipped
// silently.
export const HISTORY_MAX_BLOB_BYTES = 10 * 1024 * 1024;
// Bounds the memory one `git cat-file --batch` call can return.
const BATCH_BYTES = 64 * 1024 * 1024;
// Regular files, plus symlinks (120000): a link's "content" is its target
// text, and the commit hook scans that too - `git show :path` returns it - so
// leaving links out would make the two scans disagree. Gitlinks (160000) point
// at another repository's commit and carry no content here.
const SCANNABLE_MODES = new Set(["100644", "100755", "120000"]);
const MISSING_BLOB = "0".repeat(40);

// Every git call shares these. GIT_NO_LAZY_FETCH stops a partial clone from
// downloading every historical blob from its remote the moment one is read -
// unavailable objects are reported instead. The flags neutralise user config
// that would otherwise change what `git log` prints: log.showSignature mixes
// GPG output into stdout, and log.showRoot=false hides the root commit's files.
function git(cwd, args, input) {
  const result = spawnSync("git", args, {
    cwd,
    input,
    env: { ...process.env, GIT_NO_LAZY_FETCH: "1" },
    maxBuffer: 1024 * 1024 * 1024,
    stdio: ["pipe", "pipe", "pipe"]
  });
  if (result.error) throw result.error;
  return result;
}

function gitText(cwd, args) {
  const result = git(cwd, args);
  return result.status === 0 ? result.stdout.toString("utf8").trim() : null;
}

// Walks the history once, oldest first, and records the first commit that
// introduced each (version, path). --topo-order rather than date order: commit
// dates can run backwards after a rebase or on a skewed clock, and attribution
// must follow ancestry, not timestamps. -m includes merges, so content that
// first appears in a merge resolution is not missed.
//
// Output with -z is a stream of NUL-terminated tokens: "\x01<sha> <time>"
// headers, then ":<meta>" / "<path>" pairs. It is parsed as a state machine
// rather than split on "\x01", because a path may legally contain that byte
// and must not be able to desynchronise the parse.
export function parseRawLog(output) {
  const commits = [];
  const introduced = new Map();
  const tokens = output.split("\0");
  let current = null;

  for (let i = 0; i < tokens.length; i += 1) {
    const entry = tokens[i].replace(/^\n+/, "");
    if (entry.startsWith("\x01")) {
      const [sha, time] = entry.slice(1).split(" ");
      if (!current || current.sha !== sha) {
        // -m prints a merge once per parent; it is still one commit.
        current = { sha, time: Number(time) * 1000, index: commits.length };
        commits.push(current);
      }
      continue;
    }
    if (!entry.startsWith(":") || !current) continue;

    const path = tokens[i + 1];
    i += 1; // the path is consumed verbatim, whatever bytes it holds
    if (path === undefined) break;

    // ":<old mode> <new mode> <old sha> <new sha> <status>"
    const [, newMode, , blob, status] = entry.slice(1).split(" ");
    if (status === "D" || blob === MISSING_BLOB || !SCANNABLE_MODES.has(newMode)) continue;

    const key = `${blob}\0${path}`;
    if (!introduced.has(key)) introduced.set(key, { blob, path, commit: current });
  }

  return { commits, versions: [...introduced.values()] };
}

// "<sha> blob <size>" or "<sha> missing", one per line.
function readSizes(cwd, blobs) {
  const sizes = new Map();
  if (blobs.length === 0) return sizes;
  const result = git(cwd, ["cat-file", "--batch-check"], `${blobs.join("\n")}\n`);
  for (const line of result.stdout.toString("utf8").split("\n")) {
    const [sha, type, size] = line.split(" ");
    if (sha && type === "blob") sizes.set(sha, Number(size));
  }
  return sizes;
}

// "<sha> <type> <size>\n<content>\n" repeated, read in batches so no single
// call returns more than BATCH_BYTES.
function readContents(cwd, blobs, sizes) {
  const contents = new Map();
  let batch = [];
  let batchBytes = 0;

  const flush = () => {
    if (batch.length === 0) return;
    const output = git(cwd, ["cat-file", "--batch"], `${batch.join("\n")}\n`).stdout;
    let offset = 0;
    while (offset < output.length) {
      const headerEnd = output.indexOf(0x0a, offset);
      if (headerEnd === -1) break;
      const [sha, type, size] = output.subarray(offset, headerEnd).toString("utf8").split(" ");
      if (type !== "blob") {
        offset = headerEnd + 1;
        continue;
      }
      const start = headerEnd + 1;
      const end = start + Number(size);
      contents.set(sha, output.subarray(start, end));
      offset = end + 1; // the trailing newline after each object
    }
    batch = [];
    batchBytes = 0;
  };

  for (const blob of blobs) {
    const size = sizes.get(blob);
    if (batchBytes > 0 && batchBytes + size > BATCH_BYTES) flush();
    batch.push(blob);
    batchBytes += size;
  }
  flush();
  return contents;
}

// "(version, path)" pairs at HEAD, so each finding can say whether the leak is
// still in the current tree or exists only in history - the difference between
// "remove it now" and "it is already out there".
function versionsAtHead(cwd) {
  const result = git(cwd, ["ls-tree", "-r", "-z", "--full-tree", "HEAD"]);
  const present = new Set();
  if (result.status !== 0) return present;
  for (const entry of result.stdout.toString("utf8").split("\0")) {
    const tab = entry.indexOf("\t");
    if (tab === -1) continue;
    const [, , blob] = entry.slice(0, tab).split(" ");
    present.add(`${blob}\0${entry.slice(tab + 1)}`);
  }
  return present;
}

export function scanHistory(options = {}) {
  const cwd = options.cwd ?? process.cwd();
  const all = Boolean(options.all);
  const useAllowlist = options.allowlist !== false;

  const root = gitText(cwd, ["rev-parse", "--show-toplevel"]);
  if (!root) return { ok: false, error: "not inside a git repository" };

  const scope = all ? "all refs" : "HEAD";
  const base = { ok: true, root, scope, commitCount: 0, scannedCount: 0, findings: [], customRuleErrors: [] };
  if (!all && gitText(root, ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]) === null) {
    return { ...base, empty: true };
  }

  const log = git(root, [
    "log",
    "--topo-order",
    "--reverse",
    "-m",
    "--root",
    "--raw",
    "--no-abbrev",
    "--no-renames",
    "--no-color",
    "--no-show-signature",
    "-z",
    "--format=%x01%H %ct",
    all ? "--all" : "HEAD",
    "--"
  ]);
  if (log.status !== 0) {
    return { ok: false, error: log.stderr.toString("utf8").trim() || "git log failed" };
  }

  const { commits, versions } = parseRawLog(log.stdout.toString("utf8"));
  const blobs = [...new Set(versions.map((v) => v.blob))];
  const sizes = readSizes(root, blobs);
  const scannable = blobs.filter((b) => sizes.has(b) && sizes.get(b) <= HISTORY_MAX_BLOB_BYTES);
  const contents = readContents(root, scannable, sizes);
  const atHead = all || gitText(root, ["rev-parse", "--verify", "--quiet", "HEAD"]) ? versionsAtHead(root) : new Set();

  const allowlist = useAllowlist ? (options.allowlistPatterns ?? loadAllowlist(root)) : [];
  const dotenvSecrets = options.dotenvSecrets ?? loadDotenvSecrets(root);
  const pack = options.customRules ? { rules: options.customRules, errors: [] } : loadCustomRules(options.home);

  const findings = [];
  const allowlisted = [];
  const oversized = [];
  const unavailable = [];
  let scannedCount = 0;

  for (const version of versions) {
    if (isPathAllowlisted(version.path, allowlist)) {
      allowlisted.push(version);
      continue;
    }
    if (!sizes.has(version.blob)) {
      unavailable.push(version);
      continue;
    }
    if (sizes.get(version.blob) > HISTORY_MAX_BLOB_BYTES) {
      oversized.push({ ...version, size: sizes.get(version.blob) });
      continue;
    }

    scannedCount += 1;
    const content = decodeBlob(contents.get(version.blob));
    const fileFindings = scanFileContent(version.path, content, {
      dotenvSecrets,
      customRules: pack.rules,
      // An audit must not be blindable by the repository being audited.
      ignoreInlineAllow: !useAllowlist
    });
    const inHead = atHead.has(`${version.blob}\0${version.path}`);
    for (const finding of fileFindings) findings.push({ ...finding, commit: version.commit, inHead });
  }

  findings.sort(
    (a, b) => a.commit.index - b.commit.index || a.file.localeCompare(b.file) || a.line - b.line
  );

  return {
    ...base,
    commitCount: commits.length,
    scannedCount,
    findings,
    allowlistedCount: allowlisted.length,
    oversized,
    unavailableCount: unavailable.length,
    shallow: gitText(root, ["rev-parse", "--is-shallow-repository"]) === "true",
    customRuleErrors: pack.errors
  };
}

const plural = (count, word) => `${count} ${word}${count === 1 ? "" : "s"}`;
const LIST_LIMIT = 10;

export function formatHistoryReport(result) {
  if (!result.ok) return `gforge history: ${result.error}\n`;
  if (result.empty) {
    return "gforge history: the current branch has no commits yet - nothing to scan. Use --all to scan every ref.\n";
  }

  const lines = [];
  const byCommit = new Map();
  for (const finding of result.findings) {
    if (!byCommit.has(finding.commit.sha)) byCommit.set(finding.commit.sha, []);
    byCommit.get(finding.commit.sha).push(finding);
  }

  if (result.findings.length > 0) {
    lines.push(
      `GForge history scan - ${plural(result.findings.length, "potential secret")} in ${plural(byCommit.size, "commit")}`,
      ""
    );
    for (const [sha, findings] of byCommit) {
      const date = new Date(findings[0].commit.time).toISOString().slice(0, 10);
      lines.push(`  ${sha.slice(0, 12)}  ${date}`);
      for (const f of findings) {
        const where = f.line > 0 ? `${f.file}:${f.line}` : f.file;
        lines.push(`    ✗ ${where}  [${f.ruleId}] ${f.description}${f.inHead ? "  (still in HEAD)" : ""}`);
      }
      lines.push("");
    }
  } else {
    lines.push("GForge history scan - no secrets found", "");
  }

  lines.push(
    `Scanned ${plural(result.scannedCount, "file version")} across ${plural(result.commitCount, "commit")} (${result.scope}).`
  );
  if (result.findings.length > 0) lines.push("No secret values are printed above.");

  // Everything that was NOT scanned is said out loud: a clean result must not
  // quietly mean "clean, apart from what was skipped".
  const caveats = [];
  if (result.allowlistedCount > 0) {
    caveats.push(
      `${plural(result.allowlistedCount, "file version")} skipped by .gforgeignore/.gitleaksignore - ` +
        "rerun with --no-allowlist to include them"
    );
  }
  if (result.oversized?.length > 0) {
    const shown = result.oversized
      .slice(0, LIST_LIMIT)
      .map((v) => `${v.path} @ ${v.commit.sha.slice(0, 12)} (${(v.size / 1024 / 1024).toFixed(1)} MB)`);
    const more = result.oversized.length > LIST_LIMIT ? `, and ${result.oversized.length - LIST_LIMIT} more` : "";
    caveats.push(
      `${plural(result.oversized.length, "file version")} over ${HISTORY_MAX_BLOB_BYTES / 1024 / 1024} MB not scanned: ${shown.join(", ")}${more}`
    );
  }
  if (result.unavailableCount > 0) {
    caveats.push(
      `${plural(result.unavailableCount, "file version")} not available locally (a partial clone) were not scanned - ` +
        "GForge does not download history to scan it"
    );
  }
  if (result.shallow) caveats.push("this is a shallow clone, so history older than its depth was not scanned");
  if (result.customRuleErrors?.length > 0) {
    caveats.push(`${plural(result.customRuleErrors.length, "invalid custom rule")} in ~/.gforge/rules.json ignored`);
  }
  if (caveats.length > 0) {
    lines.push("", "Not scanned:");
    for (const caveat of caveats) lines.push(`  - ${caveat}`);
  }

  if (result.findings.length > 0) {
    lines.push(
      "",
      "A secret that was ever pushed should be treated as compromised: rotate it first.",
      "Rewriting history removes the copy, not the exposure."
    );
  }

  return `${lines.join("\n")}\n`;
}
