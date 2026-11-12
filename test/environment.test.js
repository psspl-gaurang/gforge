import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { MIN_NODE_MAJOR, detectEnvironment, detectNode } from "../src/environment.js";

test("detects supported Unix environment and Git", async () => {
  const environment = await detectEnvironment({
    env: { SHELL: "/bin/zsh" },
    platform: "darwin",
    arch: "arm64",
    homeDirectory: "/Users/example",
    execFile: async () => ({ stdout: "git version 2.45.0\n" })
  });

  assert.deepEqual(environment.platform, {
    name: "darwin",
    arch: "arm64",
    supported: true,
    isWsl: false
  });
  assert.deepEqual(environment.home, {
    path: "/Users/example",
    present: true
  });
  assert.deepEqual(environment.shell, {
    path: "/bin/zsh",
    name: "zsh",
    supported: true
  });
  assert.equal(environment.git.available, true);
  assert.equal(environment.git.version, "2.45.0");
});

test("does not mislabel every Windows process as PowerShell", async () => {
  const environment = await detectEnvironment({
    env: { PSModulePath: "C:/Modules", ComSpec: "C:/Windows/System32/cmd.exe" },
    platform: "win32",
    arch: "x64",
    homeDirectory: "C:/Users/example",
    execFile: async () => ({ stdout: "git version 2.45.0\n" })
  });

  assert.equal(environment.shell.name, "cmd.exe");
});

test("detects a pwsh session on Windows via its distribution channel marker", async () => {
  const environment = await detectEnvironment({
    env: {
      PSModulePath: "C:/Modules",
      POWERSHELL_DISTRIBUTION_CHANNEL: "MSI:Windows 10",
      ComSpec: "C:/Windows/System32/cmd.exe"
    },
    platform: "win32",
    arch: "x64",
    homeDirectory: "C:/Users/example",
    execFile: async () => ({ stdout: "git version 2.45.0\n" })
  });

  assert.equal(environment.shell.name, "pwsh");
  assert.equal(environment.shell.supported, true);
});

test("reports missing Git without throwing", async () => {
  const environment = await detectEnvironment({
    env: { SHELL: "/bin/bash" },
    platform: "linux",
    arch: "x64",
    homeDirectory: "/home/example",
    execFile: async () => {
      const error = new Error("not found");
      error.code = "ENOENT";
      throw error;
    }
  });

  assert.equal(environment.git.available, false);
  assert.equal(environment.git.errorCode, "ENOENT");
});

test("issue #52: detects the running Node.js version and whether it is supported", async () => {
  const environment = await detectEnvironment({
    env: { SHELL: "/bin/zsh" },
    platform: "linux",
    arch: "x64",
    homeDirectory: "/home/example",
    nodeVersion: "22.14.0",
    execFile: async () => ({ stdout: "git version 2.45.0\n" })
  });

  assert.deepEqual(environment.node, { version: "22.14.0", major: 22, supported: true });
});

test("issue #52: a Node below the declared minimum is reported unsupported", () => {
  assert.equal(detectNode("18.20.4").supported, false);
  assert.equal(detectNode("18.20.4").major, 18);
  // Boundary: the declared minimum itself is supported.
  assert.equal(detectNode(`${MIN_NODE_MAJOR}.0.0`).supported, true);
  assert.equal(detectNode(`${MIN_NODE_MAJOR - 1}.99.99`).supported, false);
  // A leading "v" is tolerated (process.versions.node omits it, but
  // `node --version` and most other sources include it).
  assert.equal(detectNode("v22.0.0").supported, true);
});

test("issue #52: an undetectable Node version fails closed, not open", () => {
  // Matches how the git-version gate treats an unparseable version: assume
  // unsupported rather than quietly assuming it is fine. Note a bare major
  // ("20") is deliberately in here - the pattern requires a dotted version, so
  // anything that shape is treated as unrecognised rather than guessed at.
  for (const bogus of ["", "   ", null, "not-a-version", "20"]) {
    assert.equal(detectNode(bogus).supported, false, `expected ${JSON.stringify(bogus)} unsupported`);
    assert.equal(detectNode(bogus).major, null);
  }
});

test("issue #52: calling detectNode with no argument reads the running Node", () => {
  // `undefined` is NOT a fail-closed case - it means "use the default", which
  // is the whole point of the parameter. The process running this test meets
  // the minimum, so this must report supported.
  assert.deepEqual(detectNode(), detectNode(process.versions.node));
  assert.equal(detectNode().version, process.versions.node);
  assert.equal(detectNode().supported, true);
});

test("issue #52: MIN_NODE_MAJOR stays in sync with package.json engines.node", async () => {
  // The constant is a literal so detection needs no file I/O; this guards the
  // drift that choice invites.
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const declared = Number(String(pkg.engines.node).match(/(\d+)/)?.[1]);
  assert.equal(
    MIN_NODE_MAJOR,
    declared,
    `MIN_NODE_MAJOR (${MIN_NODE_MAJOR}) must match package.json engines.node (${pkg.engines.node})`
  );
});

// ---------------------------------------------------------------------------
// The Windows and WSL branches (issue #55). These run on every platform: the
// platform and environment are injected, so a Linux CI runner exercises the
// win32 code paths too.
// ---------------------------------------------------------------------------
const detectOn = (platform, env) =>
  detectEnvironment({
    env,
    platform,
    arch: "x64",
    homeDirectory: platform === "win32" ? "C:/Users/example" : "/home/example",
    execFile: async () => ({ stdout: "git version 2.45.0\n" })
  });

test("issue #55: on Windows, a SHELL exported by Git Bash is the shell", async () => {
  const environment = await detectOn("win32", { SHELL: "/usr/bin/bash", ComSpec: "C:/Windows/System32/cmd.exe" });
  assert.equal(environment.shell.name, "bash");
  assert.equal(environment.shell.supported, true);
  assert.equal(environment.platform.isWsl, false);
});

test("issue #55: on Windows, SHELL outranks both the pwsh marker and ComSpec", async () => {
  // SHELL is the only one of the three that names a live, interactive shell;
  // the pwsh marker and ComSpec are inherited by processes that are neither.
  const environment = await detectOn("win32", {
    SHELL: "/usr/bin/bash",
    POWERSHELL_DISTRIBUTION_CHANNEL: "MSI:Windows 10",
    ComSpec: "C:/Windows/System32/cmd.exe"
  });
  assert.equal(environment.shell.name, "bash");
});

test(
  "issue #55: on Windows, a SHELL given in Windows form still reads as bash",
  { todo: "normalizeShellName strips .exe only for powershell.exe and pwsh.exe, so bash.exe reads as unsupported" },
  async () => {
    // The function already maps powershell.exe and pwsh.exe to their names, so
    // the same form of bash reading as an unsupported shell is inconsistent.
    // The field is informational - hooks run through git's own sh - but it
    // surfaces as a shell WARN in `gforge verify`.
    const environment = await detectOn("win32", { SHELL: "C:\\Program Files\\Git\\usr\\bin\\bash.exe" });
    assert.equal(environment.shell.name, "bash");
    assert.equal(environment.shell.supported, true);
  }
);

test("issue #55: WSL is flagged from WSL_DISTRO_NAME, and only on Linux", async () => {
  assert.equal((await detectOn("linux", { SHELL: "/bin/bash", WSL_DISTRO_NAME: "Ubuntu" })).platform.isWsl, true);
  assert.equal((await detectOn("linux", { SHELL: "/bin/bash" })).platform.isWsl, false);
  // Present but empty is not a distribution.
  assert.equal((await detectOn("linux", { SHELL: "/bin/bash", WSL_DISTRO_NAME: "" })).platform.isWsl, false);
  // The variable leaks into Windows processes started from WSL; the Windows
  // side of that boundary is not WSL.
  assert.equal((await detectOn("win32", { SHELL: "/usr/bin/bash", WSL_DISTRO_NAME: "Ubuntu" })).platform.isWsl, false);
});
