import { VERSION } from "./metadata.js";
import { detectEnvironment } from "./environment.js";
import {
  formatInstallResult,
  installManagedHooks,
  validateInstallPreflight,
  uninstallManagedHooks,
  updateManagedHooks,
  verifyManagedHooks
} from "./installer.js";
import {
  getLatestVersion,
  isNewer,
  performSelfUpgrade,
  readCachedUpdateNotice
} from "./npm-update.js";
import { describeDotenvSources } from "./scanner.js";
import { createVerificationReport, formatVerificationReport } from "./verify.js";

export async function runCli(args, streams, options = {}) {
  const command = args[0] ?? "help";

  if (command === "help" || command === "--help" || command === "-h") {
    streams.stdout.write(banner(streams.stdout) + helpText(streams.stdout));
    return { exitCode: 0 };
  }

  if (command === "version" || command === "--version" || command === "-v") {
    streams.stdout.write(`gforge ${VERSION}\n`);
    return { exitCode: 0 };
  }

  if (command === "install" || command === "update") {
    return runInstallOrUpdate(command, args, options, streams);
  }

  if (command === "uninstall") {
    return runMutation("uninstall", options.uninstallManagedHooks ?? uninstallManagedHooks, options, streams);
  }

  if (command === "verify") {
    const environment = await (options.detectEnvironment ?? detectEnvironment)();
    const managedHooksReport = await (options.verifyManagedHooks ?? verifyManagedHooks)({
      ...options,
      environment
    });
    const dotenvReport = (options.describeDotenvSources ?? describeDotenvSources)();
    const report = createVerificationReport(environment, managedHooksReport, dotenvReport);

    streams.stdout.write(formatVerificationReport(report));
    const notice = (options.readCachedUpdateNotice ?? readCachedUpdateNotice)(VERSION);
    if (notice) streams.stdout.write(`\n${notice}\n`);
    return { exitCode: report.exitCode };
  }

  streams.stderr.write(`${banner(streams.stderr)}Unknown command: ${command}\n\n${helpText(streams.stderr)}`);
  return { exitCode: 1 };
}

// install/update first try to upgrade the globally installed package to the
// latest published version (unless disabled), then apply the managed hooks. With
// --force, it reinstalls the latest even when already current.
async function runInstallOrUpdate(command, args, options, streams) {
  const force = args.includes("--force") || args.includes("-f");
  const selfUpdateDisabled = Boolean(process.env.GFORGE_NO_SELF_UPDATE) || options.skipSelfUpdate;

  // Validate the environment before touching the network. The self-upgrade
  // check is a registry round-trip that can take seconds, and on a machine
  // without git - or on an unsupported platform - the command was going to fail
  // regardless, so paying for that round-trip first is pure latency before an
  // error the environment already determined (issue #32).
  //
  // The detected environment is then reused by the install itself rather than
  // being detected twice.
  const environment = options.environment ?? (await (options.detectEnvironment ?? detectEnvironment)(options));
  const preflight = validateInstallPreflight(environment);
  if (preflight.length > 0) {
    streams.stderr.write(
      formatInstallResult({ ok: false, command, exitCode: 1, hooksDirectory: null, messages: preflight })
    );
    return { exitCode: 1 };
  }
  const options_ = { ...options, environment };

  if (!selfUpdateDisabled) {
    const latest = await (options.getLatestVersion ?? getLatestVersion)(options);
    // --force reinstalls the latest, but never installs a version older than the
    // one already running (no accidental downgrade when local is ahead of npm).
    const shouldUpgrade = latest && (isNewer(latest, VERSION) || (force && !isNewer(VERSION, latest)));

    if (shouldUpgrade) {
      streams.stdout.write(
        isNewer(latest, VERSION)
          ? `GForge: upgrading ${VERSION} → ${latest}...\n`
          : `GForge: reinstalling gforge@${latest} (forced)...\n`
      );
      try {
        const result = await (options.performSelfUpgrade ?? performSelfUpgrade)(command, latest, options);
        if (result.ok && result.reexeced) {
          // The freshly installed binary already ran the command with new code.
          return { exitCode: 0 };
        }
        if (result.ok) {
          // Package upgraded, but the new binary could not be re-exec'd. Set up
          // hooks now with the running code so they are actually installed.
          streams.stdout.write(`GForge: upgraded to ${latest}; setting up hooks with the current version...\n`);
        } else {
          streams.stderr.write(`GForge: upgrade failed (${result.error ?? "unknown"}); continuing with ${VERSION}.\n`);
        }
      } catch (error) {
        streams.stderr.write(`GForge: upgrade failed (${error?.message ?? error}); continuing with ${VERSION}.\n`);
      }
      // Fall through: set up/refresh hooks with the currently installed version.
    } else if (latest && force && isNewer(VERSION, latest)) {
      streams.stdout.write(`GForge: installed version (${VERSION}) is ahead of the latest published (${latest}); not downgrading. Refreshing hooks.\n`);
    } else if (latest && !isNewer(latest, VERSION)) {
      streams.stdout.write(`GForge: already on the latest version (${VERSION}).\n`);
    }
  }

  const operation = command === "install"
    ? (options.installManagedHooks ?? installManagedHooks)
    : (options.updateManagedHooks ?? updateManagedHooks);
  return runMutation(command, operation, options_, streams);
}

// Runs a state-mutating command, turning any unexpected failure (permission
// errors, an unwritable global gitconfig, etc.) into a friendly message and a
// non-zero exit code instead of an unhandled rejection and a raw stack trace.
async function runMutation(command, operation, options, streams) {
  try {
    const result = await operation(options);
    const output = formatInstallResult(result);

    if (result.ok) {
      streams.stdout.write(output);
    } else {
      streams.stderr.write(output);
    }

    return { exitCode: result.exitCode };
  } catch (error) {
    const detail = error?.message ?? String(error);
    streams.stderr.write(`GForge ${command} failed\n\n${detail}\n`);
    return { exitCode: 1 };
  }
}

const LOGO = [
  " ██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗",
  "██╔════╝ ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝",
  "██║  ███╗█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  ",
  "██║   ██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  ",
  "╚██████╔╝██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗",
  " ╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝"
].join("\n");

// Shared ANSI painter. Colors only when the target stream is an interactive
// terminal (and NO_COLOR is not set), so pipes / CI stay clean.
function makePaint(stream) {
  const color = !process.env.NO_COLOR && Boolean(stream && stream.isTTY);
  const esc = String.fromCharCode(27);
  return (code, text) => (color ? `${esc}[${code}m${text}${esc}[0m` : text);
}

// Colored GForge wordmark: logo + version + pillars form one cohesive purple mark.
function banner(stream) {
  const paint = makePaint(stream);
  const width = LOGO.split("\n")[0].length;
  const version = `v${VERSION}`.padStart(width); // bottom-right, aligned to the logo's right edge
  const rawPillars = "Secure • Standardize • Govern • Scale";
  const pillars = " ".repeat(Math.max(0, Math.floor((width - rawPillars.length) / 2))) + rawPillars; // centered under the logo
  const tagline = "  ⚒  Governance Forge - The secret firewall behind every commit.";
  return [
    paint("1;3;38;5;141", LOGO), // bold italic purple
    paint("38;5;141", version),
    paint("1;38;5;141", pillars), // bold purple: reads as part of the logo
    "",
    paint("2;3", tagline), // dim italic
    "",
    ""
  ].join("\n");
}

function helpText(stream) {
  const paint = makePaint(stream);
  const header = (t) => paint("1;38;5;141", t); // bold purple section headers (match the logo)
  const row = (n, d, pad = 14) => `  ${n.padEnd(pad)}  ${d}`; // names + descriptions: default terminal color
  return [
    header("Usage:"),
    "  gforge <command> [options]",
    "",
    header("Options:"),
    row("-h, --help", "Display this help"),
    row("-v, --version", "Display the version"),
    row("--force", "With install / update, reinstall the latest even if current"),
    "",
    header("Commands:"),
    row("install", "Upgrade to the latest version (if any) and install the hooks"),
    row("verify", "Verify the environment and installed hooks (read-only)"),
    row("update", "Upgrade to the latest version (if any) and refresh the hooks"),
    row("uninstall", "Remove GForge-owned hooks and restore your Git config"),
    row("version", "Display the version"),
    row("help", "Display this help"),
    "",
    header("Environment:"),
    row("GFORGE_AUTO_UPDATE=0", "Disable automatic background upgrades (on by default)", 30),
    row("GFORGE_NO_SELF_UPDATE=1", "Skip the npm self-upgrade in install / update", 30),
    row("GFORGE_SKIP_POSTINSTALL=1", "Skip auto-setup during npm install", 30),
    row("GFORGE_NO_DEFAULT_EXCLUDES=1", "Scan translations, docs and build output too", 30),
    ""
  ].join("\n");
}
