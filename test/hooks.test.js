import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { SCANNER_FILE_NAME, buildPreCommitHook } from "../src/hooks.js";

test("escapes install-time node path before embedding it in the hook shim", () => {
  const hook = buildPreCommitHook('C:\\Program Files\\node$dir\\`bin`\\node "lts".exe');

  assert.match(hook, /"C:\/Program Files\/node\\\$dir\/\\`bin\\`\/node \\"lts\\"\.exe"/);
  assert.match(hook, /"C:\\\\Program Files\\\\node\\\$dir\\\\\\`bin\\`\\\\node \\"lts\\"\.exe"/);
});

// ---------------------------------------------------------------------------
// The generated shim, executed (issue #55). Everything above pattern-matches its
// text; these run it through a real `sh`, the way git does, against a stub
// scanner that records how it was invoked. Each PATH is built from scratch so
// the tests decide exactly which node - if any - the shim can find.
// ---------------------------------------------------------------------------
const STUB_SCANNER = `import { appendFileSync } from "node:fs";
appendFileSync(process.env.STUB_LOG, JSON.stringify({ args: process.argv.slice(1) }) + "\\n");
process.exit(Number(process.env.STUB_EXIT ?? 0));
`;

const shimSkip = process.platform === "win32" ? "runs the shim through a POSIX sh" : false;

async function shimRig(t, nodePath) {
  // realpath so the paths the shim reports can be compared exactly: macOS's
  // temp directory sits behind a /var -> /private/var symlink.
  const root = await realpath(await mkdtemp(join(tmpdir(), "gforge-shim-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const hooks = join(root, "hooks");
  const bin = join(root, "bin");
  await mkdir(hooks);
  await mkdir(bin);

  await writeFile(join(hooks, "pre-commit"), buildPreCommitHook(nodePath));
  await chmod(join(hooks, "pre-commit"), 0o755);
  await writeFile(join(hooks, SCANNER_FILE_NAME), STUB_SCANNER);
  // dirname is the one external command the shim needs; everything else it
  // uses is an sh builtin. So this bin holds dirname and nothing else - in
  // particular, no node.
  await symlink(spawnSync("sh", ["-c", "command -v dirname"], { encoding: "utf8" }).stdout.trim(), join(bin, "dirname"));

  const log = join(root, "scanner-calls.jsonl");
  return {
    root,
    hooks,
    bin,
    scanner: join(hooks, SCANNER_FILE_NAME),
    run(env = {}) {
      const result = spawnSync("/bin/sh", [join(hooks, "pre-commit")], {
        cwd: root, // git runs hooks from the repository root, not the hooks directory
        env: { PATH: bin, STUB_LOG: log, ...env },
        encoding: "utf8"
      });
      const calls = existsSync(log)
        ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l))
        : [];
      return { ...result, calls };
    }
  };
}

test("issue #55: the shim runs the scanner in its own directory and passes its exit code through", { skip: shimSkip }, async (t) => {
  const rig = await shimRig(t, process.execPath);
  const nodeBin = dirname(process.execPath);

  const clean = rig.run({ PATH: `${rig.bin}:${nodeBin}` });
  assert.equal(clean.status, 0, clean.stderr);
  assert.deepEqual(clean.calls, [{ args: [rig.scanner, "pre-commit"] }]);

  // `exec` means the scanner's verdict IS the hook's verdict: a blocked commit
  // must reach git as a non-zero exit, whatever the code.
  for (const code of ["1", "3"]) {
    assert.equal(rig.run({ PATH: `${rig.bin}:${nodeBin}`, STUB_EXIT: code }).status, Number(code));
  }
});

test("issue #55: GFORGE_NODE wins over whatever node is on PATH", { skip: shimSkip }, async (t) => {
  const rig = await shimRig(t, "/nonexistent/node");
  // A `node` on PATH that must NOT be chosen: it exits 99 without running
  // anything.
  await writeFile(join(rig.bin, "node"), "#!/bin/sh\nexit 99\n");
  await chmod(join(rig.bin, "node"), 0o755);

  const run = rig.run({ GFORGE_NODE: process.execPath });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(run.calls, [{ args: [rig.scanner, "pre-commit"] }]);
});

test("issue #55: with no node on PATH, the shim falls back to the path baked in at install", { skip: shimSkip }, async (t) => {
  // The case the fallback exists for: a GUI git client whose PATH lacks nvm's
  // node. This PATH has no node at all.
  const rig = await shimRig(t, process.execPath);

  const run = rig.run();
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(run.calls, [{ args: [rig.scanner, "pre-commit"] }]);
});

test("issue #55: with no node anywhere, the shim fails closed and says why", { skip: shimSkip }, async (t) => {
  // A hook that cannot scan must block, not wave the commit through.
  const rig = await shimRig(t, "/nonexistent/node");

  const run = rig.run();
  assert.equal(run.status, 1);
  assert.match(run.stderr, /no Node\.js runtime found to scan for secrets; blocking commit for safety/);
  assert.match(run.stderr, /GFORGE_NODE/);
  assert.deepEqual(run.calls, [], "the scanner must not have run");
});

test("issue #55: on Git for Windows the scanner path is translated with cygpath", { skip: shimSkip }, async (t) => {
  // Under MSYS sh, a native node.exe cannot open a POSIX path, so the shim
  // hands it cygpath's Windows form. Simulated with a cygpath that maps the
  // scanner to a second, distinguishable copy - and one that fails, which must
  // fall back to the untranslated path rather than to nothing.
  const rig = await shimRig(t, process.execPath);
  const translated = join(rig.root, "translated", SCANNER_FILE_NAME);
  await mkdir(dirname(translated));
  await writeFile(translated, STUB_SCANNER);

  await writeFile(join(rig.bin, "cygpath"), `#!/bin/sh\n[ "$1" = "-w" ] && printf '%s' ${JSON.stringify(translated)}\n`);
  await chmod(join(rig.bin, "cygpath"), 0o755);
  const mapped = rig.run();
  assert.equal(mapped.status, 0, mapped.stderr);
  assert.deepEqual(mapped.calls, [{ args: [translated, "pre-commit"] }]);

  await writeFile(join(rig.bin, "cygpath"), "#!/bin/sh\nexit 1\n");
  const fallback = rig.run();
  assert.equal(fallback.status, 0, fallback.stderr);
  assert.deepEqual(fallback.calls.at(-1), { args: [rig.scanner, "pre-commit"] });
});
