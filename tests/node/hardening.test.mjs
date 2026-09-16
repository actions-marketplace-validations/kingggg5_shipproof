import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import test from "node:test";

import { internals as cliInternals, runCli } from "../../lib/cli.mjs";
import { internals as evidenceInternals } from "../../lib/evidence.mjs";
import { buildScanArguments, internals as mcpInternals } from "../../lib/mcp-server.mjs";
import { parsePolicyText, validatePolicy } from "../../lib/policy.mjs";
import { detectPythonRuntime, isSupportedPythonVersion } from "../../lib/runtime.mjs";
import { formatActionSummary } from "../../scripts/run-action.mjs";
import { resolveTrustedExecutable } from "../../lib/executable.mjs";

const { runPythonJsonCommand } = cliInternals;

test("imported identity requires both digests and never attests the review", () => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-import-identity-"));
  try {
    const path = join(root, "evidence.json");
    writeFileSync(path, JSON.stringify({
      schema_version: "1.0", tool: { name: "fixture", version: "1.0.0", command: "review" },
      verdict: "REVIEW", limitations: ["synthetic"], target_digest: "a".repeat(64),
      config_digest: "b".repeat(64), captured_at: "2026-01-01T00:00:00Z", findings: [],
    }));
    for (const options of [{ expectTarget: "a".repeat(64) }, { expectConfig: "b".repeat(64) }]) {
      const report = evidenceInternals.loadImportedEvidence(path, options);
      assert.equal(report.identity_matches, false);
      assert.equal(report.resume_eligible, false);
      assert.equal(report.gate_eligible, false);
    }
    const verified = evidenceInternals.loadImportedEvidence(path, {
      expectTarget: "a".repeat(64), expectConfig: "b".repeat(64),
    });
    assert.equal(verified.identity_matches, true);
    assert.equal(verified.gate_eligible, false);
    for (const value of [NaN, Infinity, -1, true]) {
      assert.throws(() => evidenceInternals.loadImportedEvidence(path, { clockSkewMinutes: value }), /finite non-negative/);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function fakeSpawn(overrides = {}) {
  return (_command, _args, _options) => ({
    status: 0,
    stdout: JSON.stringify({ verdict: "PASS_WITH_EVIDENCE" }),
    stderr: "",
    ...overrides,
  });
}

test("runtime detection is shared, cached, and version-gated", () => {
  assert.equal(isSupportedPythonVersion("Python 3.10.0"), true);
  assert.equal(isSupportedPythonVersion("Python 3.9.7"), false);
  assert.equal(isSupportedPythonVersion(""), false);
  const runtime = detectPythonRuntime({ refresh: true });
  if (runtime) {
    assert.match(runtime.version, /Python 3\.(?:[1-9]\d|\d{2,})/);
    const cached = detectPythonRuntime();
    assert.equal(cached.command, runtime.command);
  }
});

test("runPythonJsonCommand maps timeout kills to an actionable error", () => {
  assert.throws(
    () => runPythonJsonCommand("skills/x/y.py", [], () => ({ status: null, signal: "SIGTERM", stdout: "", stderr: "" })),
    /terminated.*timeout/i,
  );
});

test("runPythonJsonCommand maps maxBuffer failures to an actionable error", () => {
  const error = new Error("stdout maxBuffer length exceeded");
  assert.throws(
    () => runPythonJsonCommand("skills/x/y.py", [], () => ({ error, status: null, stdout: "", stderr: "" })),
    /output limit.*SHIPPROOF_MAX_BUFFER_BYTES/,
  );
});

test("runPythonJsonCommand surfaces scanner stderr for invalid evidence", () => {
  assert.throws(
    () => runPythonJsonCommand("skills/x/y.py", [], () => ({ status: 3, stdout: "", stderr: "boom" })),
    /boom/,
  );
});

test("runPythonJsonCommand names the gate when JSON is invalid", () => {
  assert.throws(
    () => runPythonJsonCommand("skills/x/y.py", [], fakeSpawn({ stdout: "not-json" })),
    /skills\/x\/y\.py.*invalid JSON/,
  );
});

test("gate environment is parsed lazily and does not break informational commands", () => {
  const previous = process.env.SHIPPROOF_GATE_TIMEOUT_MS;
  process.env.SHIPPROOF_GATE_TIMEOUT_MS = "invalid";
  try {
    assert.equal(runCli(["--version"]), 0);
    assert.throws(() => cliInternals.resolveGateLimits(), /SHIPPROOF_GATE_TIMEOUT_MS/);
  } finally {
    if (previous === undefined) delete process.env.SHIPPROOF_GATE_TIMEOUT_MS;
    else process.env.SHIPPROOF_GATE_TIMEOUT_MS = previous;
  }
});

test("legacy MCP cache setting remains bounded even though verdict reuse is removed", () => {
  const previous = process.env.SHIPPROOF_MCP_CACHE_MS;
  try {
    for (const value of ["invalid", "-1", "1.5", "3600001"]) {
      process.env.SHIPPROOF_MCP_CACHE_MS = value;
      assert.throws(() => mcpInternals.resolveMcpSettings(), /SHIPPROOF_MCP_CACHE_MS/);
    }
    for (const value of ["0", "60000", "3600000"]) {
      process.env.SHIPPROOF_MCP_CACHE_MS = value;
      assert.equal(mcpInternals.resolveMcpSettings().cacheMs, Number(value));
    }
  } finally {
    if (previous === undefined) delete process.env.SHIPPROOF_MCP_CACHE_MS;
    else process.env.SHIPPROOF_MCP_CACHE_MS = previous;
  }
});

test("trusted executable resolution rejects repository shadowing and relative PATH entries", () => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-executable-root-"));
  const outside = mkdtempSync(join(tmpdir(), "shipproof-executable-host-"));
  const filename = process.platform === "win32" ? "py.exe" : "py";
  const insideCommand = join(root, filename);
  const outsideCommand = join(outside, filename);
  try {
    writeFileSync(insideCommand, "shadow", "utf8");
    writeFileSync(outsideCommand, "trusted", "utf8");
    if (process.platform !== "win32") {
      chmodSync(insideCommand, 0o755);
      chmodSync(outsideCommand, 0o755);
    }
    assert.equal(
      resolveTrustedExecutable("py", { root, environment: { PATH: root } }),
      null,
    );
    assert.equal(
      resolveTrustedExecutable("py", {
        root,
        environment: { PATH: `.${delimiter}${outside}` },
      }),
      realpathSync.native(outsideCommand),
    );
    assert.equal(
      resolveTrustedExecutable("py", {
        root,
        environment: { PATH: `${root}${delimiter}${outside}` },
      }),
      realpathSync.native(outsideCommand),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test("trusted executable resolution rejects a repository symlink PATH parent", (context) => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-executable-link-root-"));
  const outside = mkdtempSync(join(tmpdir(), "shipproof-executable-link-host-"));
  const filename = process.platform === "win32" ? "py.exe" : "py";
  try {
    const outsideCommand = join(outside, filename);
    writeFileSync(outsideCommand, "trusted", "utf8");
    if (process.platform !== "win32") chmodSync(outsideCommand, 0o755);
    const linkedDirectory = join(root, "bin-link");
    try {
      symlinkSync(outside, linkedDirectory, process.platform === "win32" ? "junction" : undefined);
    } catch (error) {
      context.skip(`symlink creation unavailable: ${error.code || error.message}`);
      return;
    }
    assert.equal(
      resolveTrustedExecutable("py", { root, environment: { PATH: linkedDirectory } }),
      null,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test("trusted executable resolution follows a host PATH symlink", (context) => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-executable-hostlink-root-"));
  const outside = mkdtempSync(join(tmpdir(), "shipproof-executable-hostlink-host-"));
  const filename = process.platform === "win32" ? "py.exe" : "py";
  try {
    const outsideCommand = join(outside, filename);
    writeFileSync(outsideCommand, "trusted", "utf8");
    if (process.platform !== "win32") chmodSync(outsideCommand, 0o755);
    const linkedName = process.platform === "win32" ? "python3.exe" : "python3";
    const linkedCommand = join(outside, linkedName);
    try {
      symlinkSync(outsideCommand, linkedCommand);
    } catch (error) {
      context.skip(`symlink creation unavailable: ${error.code || error.message}`);
      return;
    }
    assert.equal(
      resolveTrustedExecutable(process.platform === "win32" ? "python3.exe" : "python3", {
        root,
        environment: { PATH: outside },
      }),
      realpathSync.native(outsideCommand),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test("MCP environment validation is lazy and bounded", () => {
  const previous = process.env.SHIPPROOF_MCP_TIMEOUT_MS;
  process.env.SHIPPROOF_MCP_TIMEOUT_MS = "invalid";
  try {
    assert.throws(() => mcpInternals.resolveMcpSettings(), /SHIPPROOF_MCP_TIMEOUT_MS/);
  } finally {
    if (previous === undefined) delete process.env.SHIPPROOF_MCP_TIMEOUT_MS;
    else process.env.SHIPPROOF_MCP_TIMEOUT_MS = previous;
  }
});

test("buildScanArguments supports exclude, confidence, and cross-file modes", () => {
  assert.deepEqual(
    buildScanArguments({ path: ".", fail_on: "high", max_file_bytes: 1000 }),
    [".", "--format", "json", "--fail-on", "high", "--max-file-bytes", "1000", "--fail-on-incomplete", "--trace"],
  );
  assert.deepEqual(
    buildScanArguments({ path: ".", exclude: ["dist/**", "build/**"], cross_file: true, min_confidence: "medium" }),
    [
      ".", "--format", "json", "--fail-on", "high", "--max-file-bytes", "1000000",
      "--exclude", "dist/**", "--exclude", "build/**",
      "--min-confidence", "medium",
      "--cross-file",
      "--fail-on-incomplete", "--trace",
    ],
  );
});

test("buildScanArguments rejects malformed exclude patterns", () => {
  assert.throws(() => buildScanArguments({ path: ".", exclude: [""] }), /repository-relative/);
  assert.throws(() => buildScanArguments({ path: ".", exclude: ["a\nb"] }), /repository-relative/);
  assert.throws(() => buildScanArguments({ path: ".", exclude: ["x".repeat(600)] }), /repository-relative/);
  assert.throws(() => buildScanArguments({ path: ".", min_confidence: "certain" }), /min_confidence/);
});

test("mcp internals stay exported for parity tooling", () => {
  assert.equal(typeof mcpInternals.runPythonJson, "function");
  assert.equal(typeof mcpInternals.runPythonProcess, "function");
});

test("MCP coverage gate accepts only a boolean and is strict by default", () => {
  for (const enabled of [undefined, false, true]) {
    const argumentsList = buildScanArguments({ path: ".", fail_on_incomplete: enabled });
    assert.equal(argumentsList.includes("--fail-on-incomplete"), enabled !== false);
    assert.equal(argumentsList.includes("--allow-incomplete"), enabled === false);
  }
  for (const invalid of ["false", "true", 0, 1, null, [], {}]) {
    assert.throws(() => buildScanArguments({ path: ".", fail_on_incomplete: invalid }), /must be a boolean/);
  }
});

test("Action summaries expose incomplete coverage even if the severity gate passes", () => {
  const directory = mkdtempSync(join(tmpdir(), "shipproof-summary-coverage-"));
  try {
    for (const format of ["json", "sarif"]) {
      const completeness = { is_complete: false, reasons: ["containers"], containers: 1 };
      const report = format === "json"
        ? { verdict: "CONDITIONAL", summary: { completeness }, findings: [] }
        : { runs: [{ properties: { completeness }, results: [] }] };
      const path = join(directory, `report.${format}`);
      writeFileSync(path, JSON.stringify(report), "utf8");
      const summary = formatActionSummary(path, format, { exitCode: 0 });
      assert.match(summary, /PASSED/);
      assert.match(summary, /Coverage: \*\*INCOMPLETE\*\*/);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("policy parser rejects mapping-shaped sequence items", () => {
  assert.throws(
    () => parsePolicyText("version: 1\nscan:\n  exclude:\n    - path: dist\n"),
    /plain scalars.*mappings/,
  );
});

test("policy parser explains leading-zero numbers", () => {
  assert.throws(
    () => parsePolicyText("version: 1\nscan:\n  max_file_bytes: 007\n"),
    /leading zeros/,
  );
});

test("policy parser reports JSON syntax errors with context", () => {
  assert.throws(() => parsePolicyText('{"version": 1,'), /invalid JSON policy/);
});

test("policy parser unifies max_file_bytes floor with the action and MCP", () => {
  assert.throws(
    () => validatePolicy(parsePolicyText("version: 1\nscan:\n  max_file_bytes: 512\n")),
    /1024/,
  );
  const policy = validatePolicy(parsePolicyText("version: 1\nscan:\n  max_file_bytes: 1024\n"));
  assert.equal(policy.scan.max_file_bytes, 1024);
});

test("evidence diagnostics are classified by severity", () => {
  const { classifyDiagnostics } = evidenceInternals;
  assert.deepEqual(
    classifyDiagnostics([
      "src/main.rs:12:5: error: unresolved import",
      "src/lib.rs:3:1: warning: unused variable",
      "src/lib.rs:9:8: warning: value assigned is never read",
      "vet: suspicious Printf call",
    ]),
    { error: 1, warning: 2, other: 1 },
  );
});

test("evidence diagnostics redact common credential forms", () => {
  const { redactDiagnosticLine } = evidenceInternals;
  const name = "api_" + "key";
  const value = "fixture-value-that-must-not-escape";
  const redacted = redactDiagnosticLine(`src/app.ts:1: error: ${name}=${value}`);
  assert.match(redacted, /\[REDACTED\]/);
  assert.equal(redacted.includes(value), false);
  assert.equal(redactDiagnosticLine("https://user:pass@example.invalid"), "https://[REDACTED]@example.invalid");
});

test("policy parser still accepts quoted strings containing colons in sequences", () => {
  const policy = parsePolicyText('version: 1\nscan:\n  exclude:\n    - "01-intro:/**"\n');
  assert.deepEqual(policy.scan.exclude, ["01-intro:/**"]);
});

test("action summary escapes table cells and caps rendered rows", () => {
  const directory = mkdtempSync(join(tmpdir(), "shipproof-summary-"));
  const reportPath = join(directory, "report.json");
  const findings = Array.from({ length: 230 }, (_, index) => ({
    severity: "high",
    rule_id: `SP9${String(index).padStart(2, "0")}`,
    path: `src/file|${index}.ts`,
    line: index + 1,
    title: `Title with | pipe and\nnewline ${index}`,
  }));
  writeFileSync(reportPath, JSON.stringify({ verdict: "BLOCK", findings, summary: { files_scanned: 1 } }));
  const summary = formatActionSummary(reportPath, "json", { exitCode: 1, failOn: "high" });
  assert.match(summary, /Title with \\\| pipe and newline/);
  assert.match(summary, /…and 30 more findings/);
  assert.equal((summary.match(/\n/g) || []).length < 260, true);
  rmSync(directory, { recursive: true, force: true });
});

test("action summary does not read oversized reports", () => {
  const directory = mkdtempSync(join(tmpdir(), "shipproof-summary-large-"));
  const reportPath = join(directory, "report.md");
  writeFileSync(reportPath, "x".repeat(1_000_001));
  const summary = formatActionSummary(reportPath, "markdown", {
    exitCode: 1,
    failOn: "high",
  });
  assert.match(summary, /Summary omitted/);
  assert.equal(summary.includes("x".repeat(1_000)), false);
  rmSync(directory, { recursive: true, force: true });
});

test("scan turns omitted content into exit 1 by default", () => {
  const directory = mkdtempSync(join(tmpdir(), "shipproof-coverage-"));
  const CLI = join(cliInternals.PACKAGE_ROOT, "bin", "shipproof.mjs");
  try {
    writeFileSync(join(directory, "app.py"), "value = 1;\n", "utf8");
    writeFileSync(join(directory, "bundle.zip"), "PK\x03\x04 not inspected", "utf8");
    const base = [
      process.execPath, CLI, "scan", directory,
      "--format", "json", "--fail-on", "none",
    ];
    const strict = spawnSync(base[0], base.slice(1), { encoding: "utf8", shell: false, windowsHide: true });
    assert.equal(strict.status, 1, strict.stderr);
    const report = JSON.parse(strict.stdout);
    assert.equal(report.summary.completeness.is_complete, false);
    assert.deepEqual(report.summary.completeness.reasons, ["containers"]);

    assert.match(strict.stderr, /coverage incomplete/);
    const exploratory = spawnSync(
      process.execPath,
      [...base.slice(1, 4), "--allow-incomplete"],
      { encoding: "utf8", shell: false, windowsHide: true },
    );
    assert.equal(exploratory.status, 0, exploratory.stderr);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("policy check preserves incomplete evidence and enforces the fail-closed gate", () => {
  const directory = mkdtempSync(join(tmpdir(), "shipproof-policy-coverage-"));
  const CLI = join(cliInternals.PACKAGE_ROOT, "bin", "shipproof.mjs");
  try {
    writeFileSync(join(directory, "bundle.zip"), "uninspected container", "utf8");
    for (const failOnIncomplete of [false, true]) {
      writeFileSync(join(directory, ".shipproof.yml"), JSON.stringify({
        version: 1, security: { fail_on: "none", fail_on_incomplete: failOnIncomplete },
      }), "utf8");
      const result = spawnSync(process.execPath, [CLI, "check", directory, "--format", "json"], {
        encoding: "utf8", shell: false, windowsHide: true,
      });
      // `check` is fail-closed even when repository policy attempts to opt out
      // of incomplete evidence or lowers the severity threshold.
      assert.equal(result.status, 1, result.stderr);
      const report = JSON.parse(result.stdout);
      assert.equal(report.passed, false);
      assert.equal(report.verdict, "BLOCK");
      assert.equal(report.gates[0].evidence.summary.completeness.is_complete, false);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("check ignores repository attempts to lower the security floor or narrow scan scope", () => {
  const directory = mkdtempSync(join(tmpdir(), "shipproof-policy-floor-"));
  const CLI = join(cliInternals.PACKAGE_ROOT, "bin", "shipproof.mjs");
  try {
    mkdirSync(join(directory, "safe"));
    writeFileSync(join(directory, "safe", ".keep"), "", "utf8");
    writeFileSync(join(directory, "app.py"), "value = ev" + "al(input)\n", "utf8");
    writeFileSync(
      join(directory, ".shipproof.yml"),
      "version: 1\nscan:\n  path: safe\n  exclude:\n    - app.py\nsecurity:\n  fail_on: none\n",
      "utf8",
    );
    const result = spawnSync(process.execPath, [CLI, "check", directory, "--format", "json"], {
      encoding: "utf8",
      shell: false,
      windowsHide: true,
    });
    assert.equal(result.status, 1, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.passed, false);
    assert.equal(report.verdict, "BLOCK");
    assert.equal(report.gates[0].status, "fail");
    assert.equal(report.gates[0].evidence.findings[0].rule_id, "SP101");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
