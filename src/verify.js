import { MIN_NODE_MAJOR } from "./environment.js";

export function createVerificationReport(
  environment,
  managedHooksReport = null,
  dotenvReport = null,
  sharedAllowlistReport = null
) {
  const checks = [
    {
      status: environment.platform.supported ? "PASS" : "FAIL",
      label: "platform",
      detail: `${environment.platform.name} ${environment.platform.arch}`.trim()
    },
    {
      status: environment.home.present ? "PASS" : "FAIL",
      label: "home",
      detail: environment.home.path ?? "not detected"
    },
    {
      status: environment.shell.supported ? "PASS" : "WARN",
      label: "shell",
      detail: formatShell(environment.shell)
    },
    {
      status: environment.git.available ? "PASS" : "FAIL",
      label: "git",
      detail: environment.git.available ? environment.git.rawVersion : "git not found"
    },
    nodeCheck(environment.node)
  ];

  const allChecks = [
    ...checks,
    ...(managedHooksReport ? managedHooksReport.checks : []),
    ...dotenvChecks(dotenvReport),
    ...sharedAllowlistChecks(sharedAllowlistReport)
  ];

  // A WARN normally means "worth knowing, still protected" — an unsupported
  // shell, or one scanner layer being inactive while the others run. But a
  // check may also mark itself `blocking`, meaning scanning is not active at
  // all. Those must fail the exit code: `gforge verify && deploy` previously
  // passed in a repository whose own core.hooksPath shadows the managed hooks,
  // where the WARN's own text says GForge will not run (issue #42).
  //
  // Deliberately keyed off an explicit flag rather than "any WARN": failing on
  // every WARN would break CI for repositories that simply have no .env file,
  // which is not a protection gap.
  const blocking = allChecks.filter((check) => check.blocking);

  return {
    checks: allChecks,
    blocking,
    exitCode: allChecks.some((check) => check.status === "FAIL") || blocking.length > 0 ? 1 : 0
  };
}

// The shared allowlist is the one configuration that makes GForge scan LESS, and
// it lives outside the repository, so nothing in a project's own files hints
// that it is in effect. Reported for the same reason a shadowed hooksPath is:
// a developer looking at a clean verify should be able to see what is being
// skipped and where that came from (issue #94). Counts and the path only -
// never the entries.
//
// Not `blocking`: an allowlist is a deliberate choice, not a protection gap.
// A refused entry is a WARN because it silently stopped allowlisting, which is
// the safe direction but not the one its author intended.
function sharedAllowlistChecks(report) {
  if (!report || !report.present) return [];

  const label = "shared-allowlist";
  if (report.refusedCount > 0) {
    return [{
      status: "WARN",
      label,
      detail:
        `${report.entryCount} entr(ies) from ${report.path}, ` +
        `${report.refusedCount} refused as too long or catastrophically backtracking - ` +
        "those fall back to substring matching"
    }];
  }

  return [{
    status: "PASS",
    label,
    detail: `${report.entryCount} entr(ies) from ${report.path}`
  }];
}

// The .env cross-reference is the scanner's highest-precision layer, and it is
// inert whenever no .env file is readable — a monorepo with only per-package
// env files used to report perfect health while catching nothing (issue #26).
// Verification says what the layer can see: paths and counts, never values.
// Nothing is reported outside a git repository, where there is no repo to read.
function dotenvChecks(report) {
  if (!report || !report.inRepo) return [];

  const label = "dotenv-cross-reference";
  if (report.files.length === 0) {
    return [{ status: "WARN", label, detail: "no .env file found in this repository; layer inactive" }];
  }
  if (report.secretCount === 0) {
    return [{
      status: "WARN",
      label,
      detail: `${formatFileList(report.files)} hold no secret-shaped values; layer inactive`
    }];
  }

  return [{
    status: "PASS",
    label,
    detail: `${report.secretCount} value(s) cross-referenced from ${formatFileList(report.files)}`
  }];
}

function formatFileList(files, limit = 4) {
  const shown = files.slice(0, limit).join(", ");
  const rest = files.length - limit;
  return rest > 0 ? `${files.length} env files (${shown}, +${rest} more)` : shown;
}

export function formatVerificationReport(report) {
  const lines = ["GForge read-only verification", ""];

  for (const check of report.checks) {
    lines.push(`${check.status} ${check.label}: ${check.detail}`);
  }

  // Without this, a non-zero exit driven by a WARN-status check reads as
  // inexplicable: every line says PASS or WARN, yet the command failed.
  if (report.blocking?.length) {
    lines.push("");
    lines.push(
      `Not protected: ${report.blocking.map((check) => check.label).join(", ")} — secret scanning is not active here, so verification failed.`
    );
  }

  return `${lines.join("\n")}\n`;
}

// The package declares engines.node, but npm only enforces that under
// engine-strict - so gforge can be running right now on a Node it does not
// support, with nothing saying so. Not marked `blocking`: unlike a shadowed
// hooksPath, an old runtime does not prove scanning is inactive, it proves it
// is untested. FAIL is still right, since the exit code should not call an
// unsupported runtime healthy (issue #52).
function nodeCheck(node) {
  if (!node) {
    return { status: "FAIL", label: "node", detail: "Node.js version not detected" };
  }
  if (node.supported) {
    return { status: "PASS", label: "node", detail: `Node.js ${node.version}` };
  }
  // An unparseable version is not "below" the minimum, it is unreadable - say
  // which one it actually is rather than implying a comparison that never ran.
  const problem =
    node.major === null
      ? `could not read the Node.js version${node.version ? ` (got "${node.version}")` : ""}`
      : `Node.js ${node.version} is below the required Node.js ${MIN_NODE_MAJOR}`;
  return {
    status: "FAIL",
    label: "node",
    detail: `${problem} - GForge is untested here and may fail in ways that look unrelated. Upgrade Node.`
  };
}

function formatShell(shell) {
  if (!shell.name) {
    return "not detected";
  }

  return shell.path && shell.path !== shell.name ? `${shell.name} (${shell.path})` : shell.name;
}
