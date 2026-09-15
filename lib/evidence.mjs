import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";

import { VERSION } from "./package-info.mjs";
import { resolveTrustedExecutable } from "./executable.mjs";
import { resolveRepositoryPath } from "./safe-path.mjs";

const PROBE_TIMEOUT_MS = 3_000;
const ADAPTER_TIMEOUT_MS = 120_000;
const ADAPTER_MAX_BUFFER_BYTES = 2_000_000;
const MAX_DIAGNOSTIC_LINES = 200;
const MAX_DIAGNOSTIC_LINE_CHARS = 4_096;
const MAX_IMPORT_BYTES = 2_000_000;
const IMPORT_DIGEST = /^[0-9a-f]{64}$/;
const IMPORT_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const IMPORT_VERDICTS = new Set(["PASS", "PASS_WITH_EVIDENCE", "CONDITIONAL", "WARN", "REVIEW", "BLOCK"]);
const IMPORT_SEVERITIES = new Set(["critical", "high", "medium", "low"]);

const ADAPTERS = Object.freeze({
  typescript: {
    marker: "tsconfig.json",
    description: "TypeScript compiler diagnostics",
    build(root) {
      const compiler = join(root, "node_modules", "typescript", "bin", "tsc");
      try {
        const metadata = lstatSync(compiler);
        if (!metadata.isFile() || metadata.isSymbolicLink()) return null;
      } catch {
        return null;
      }
      const resolvedCompiler = resolveRepositoryPath(
        root,
        join("node_modules", "typescript", "bin", "tsc"),
        "file",
      );
      return {
        command: process.execPath,
        argumentsList: [resolvedCompiler, "--noEmit", "--pretty", "false"],
        versionArguments: [resolvedCompiler, "--version"],
        versionRequiresProjectCodeApproval: true,
      };
    },
    requiresProjectCodeApproval: true,
    approvalReason: "typescript analysis executes the repository-local compiler",
    diagnosticExitCodes: [1, 2],
  },
  go: {
    marker: "go.mod",
    description: "Go vet diagnostics with dependency downloads disabled",
    build() {
      return { command: "go", argumentsList: ["vet", "./..."], versionArguments: ["version"] };
    },
    environment: { GOPROXY: "off", GOTOOLCHAIN: "local" },
    diagnosticExitCodes: [1],
  },
  rust: {
    marker: "Cargo.toml",
    description: "Rust Clippy diagnostics in offline mode",
    build() {
      return {
        command: "cargo",
        argumentsList: ["clippy", "--offline", "--all-targets", "--message-format=short", "--", "-D", "warnings"],
        versionArguments: ["--version"],
      };
    },
    requiresProjectCodeApproval: true,
    approvalReason: "rust analysis may execute build.rs",
    diagnosticExitCodes: [101],
  },
});

function repositoryRoot(inputPath) {
  const root = realpathSync.native(resolve(inputPath || "."));
  if (!statSync(root).isDirectory()) throw new Error(`not a directory: ${root}`);
  return root;
}

function resolveInvocation(invocation, root, environment) {
  if (!invocation) return null;
  const command = resolveTrustedExecutable(invocation.command, {
    root,
    environment,
    // The only project-local executable is TypeScript's compiler, but its
    // process is Node (process.execPath), not the repository path. Project
    // code approval is enforced by the adapter before execution.
    allowInsideRoot: false,
  });
  return command ? { ...invocation, command } : null;
}

function probeExecutable(command, environment, root, versionArguments = ["--version"]) {
  const resolvedCommand = resolveTrustedExecutable(command, { root, environment });
  if (!resolvedCommand) return { available: false, version: null };
  const result = spawnSync(resolvedCommand, versionArguments, {
    cwd: root,
    encoding: "utf8",
    env: environment,
    shell: false,
    timeout: PROBE_TIMEOUT_MS,
    windowsHide: true,
  });
  const version = redactDiagnosticLine(`${result.stdout || ""}${result.stderr || ""}`.trim());
  return {
    available: result.status === 0 && !result.error && Boolean(version),
    version: result.status === 0 && !result.error && version ? version.slice(0, 256) : null,
  };
}

export function discoverEvidenceAdapters(inputPath = ".", { allowProjectCode = false } = {}) {
  const root = repositoryRoot(inputPath);
  return Object.entries(ADAPTERS).map(([name, adapter]) => {
    const detected = existsSync(join(root, adapter.marker));
    const environment = { ...process.env, ...adapter.environment };
    const invocation = detected
      ? resolveInvocation(adapter.build(root), root, environment)
      : null;
    // A discovery/list operation must not execute a repository-controlled
    // analyzer merely to read its version.  Rust's `cargo clippy` may run
    // build.rs, and the TypeScript compiler is repository-local, so both are
    // project-code execution boundaries.  Keep the approval decision at the
    // adapter level rather than relying on an invocation-specific hint; this
    // makes `--list` and future adapters fail closed by default.
    const approvalRequired = Boolean(
      adapter.requiresProjectCodeApproval && !allowProjectCode,
    );
    const probe = invocation && !approvalRequired
      ? probeExecutable(invocation.command, environment, root, invocation.versionArguments)
      : { available: false, version: null };
    return {
      name,
      description: adapter.description,
      detected,
      available: probe.available,
      analyzer_version: probe.version,
      approval_required: approvalRequired,
      requires_project_code_approval: Boolean(adapter.requiresProjectCodeApproval),
    };
  });
}

export function redactDiagnosticLine(value) {
  return String(value || "")
    .replace(/\bBearer\s+[^\s,;]+/giu, "Bearer [REDACTED]")
    .replace(
      /\b((?:password|passwd|token|secret|api[_-]?key|authorization|cookie)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu,
      "$1[REDACTED]",
    )
    .replace(/\b(?:gh[pousr]_|sk-(?:proj-)?)[A-Za-z0-9_-]{12,}/gu, "[REDACTED]")
    .replace(/\bAKIA[A-Z0-9]{16}\b/gu, "[REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/gu, "[REDACTED]")
    .replace(/:\/\/[^\s/:@]+:[^\s/@]+@/gu, "://[REDACTED]@");
}

function boundedDiagnostics(stdout, stderr) {
  const sourceLines = `${stdout || ""}\n${stderr || ""}`
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter(Boolean);
  const diagnostics = sourceLines.slice(0, MAX_DIAGNOSTIC_LINES).map((line) => {
    const redacted = redactDiagnosticLine(line);
    return redacted.length > MAX_DIAGNOSTIC_LINE_CHARS
      ? `${redacted.slice(0, MAX_DIAGNOSTIC_LINE_CHARS)}…[truncated]`
      : redacted;
  });
  return {
    diagnostics,
    truncated: sourceLines.length > MAX_DIAGNOSTIC_LINES
      || sourceLines.some((line) => redactDiagnosticLine(line).length > MAX_DIAGNOSTIC_LINE_CHARS),
  };
}

export function classifyDiagnostics(diagnostics) {
  const counts = { error: 0, warning: 0, other: 0 };
  for (const line of diagnostics) {
    if (/:\s*error\b/i.test(line)) counts.error += 1;
    else if (/:\s*warning\b/i.test(line)) counts.warning += 1;
    else counts.other += 1;
  }
  return counts;
}

export function runEvidenceAdapter(
  inputPath,
  adapterName,
  {
    allowProjectCode = false,
    timeoutMs = ADAPTER_TIMEOUT_MS,
    maxBufferBytes = ADAPTER_MAX_BUFFER_BYTES,
  } = {},
) {
  const root = repositoryRoot(inputPath);
  const adapter = ADAPTERS[adapterName];
  if (!adapter) throw new Error(`unsupported adapter: ${adapterName}`);
  if (!existsSync(join(root, adapter.marker))) {
    throw new Error(`${adapterName} adapter did not find ${adapter.marker}`);
  }
  if (adapter.requiresProjectCodeApproval && !allowProjectCode) {
    throw new Error(`${adapter.approvalReason}; pass --allow-project-code after review`);
  }
  const environment = { ...process.env, ...adapter.environment };
  const invocation = resolveInvocation(adapter.build(root), root, environment);
  const probe = invocation
    ? probeExecutable(invocation.command, environment, root, invocation.versionArguments)
    : { available: false, version: null };
  if (!invocation || !probe.available) {
    throw new Error(`${adapterName} analyzer is not installed or not available offline`);
  }
  const result = spawnSync(invocation.command, invocation.argumentsList, {
    cwd: root,
    encoding: "utf8",
    env: environment,
    maxBuffer: maxBufferBytes,
    shell: false,
    timeout: timeoutMs,
    windowsHide: true,
  });
  if (result.error?.code === "ETIMEDOUT") {
    throw new Error(`${adapterName} analyzer timed out without usable evidence`);
  }
  if (result.error?.code === "ENOBUFS") {
    throw new Error(`${adapterName} analyzer exceeded the output cap without usable evidence`);
  }
  if (result.error) throw new Error(`${adapterName} analyzer failed without usable evidence`);
  if (result.signal || result.status === null) {
    throw new Error(`${adapterName} analyzer terminated without usable evidence`);
  }
  const bounded = boundedDiagnostics(result.stdout, result.stderr);
  const diagnostics = bounded.diagnostics;
  if (
    result.status !== 0
    && !adapter.diagnosticExitCodes?.includes(result.status)
  ) {
    throw new Error(`${adapterName} analyzer failed with exit code ${result.status}`);
  }
  if (result.status !== 0 && diagnostics.length === 0) {
    throw new Error(`${adapterName} analyzer failed without diagnostics`);
  }
  const passed = result.status === 0;
  return {
    schema_version: "1.0",
    tool: { name: "ShipProof", version: VERSION, command: "evidence" },
    verdict: passed ? "PASS_WITH_EVIDENCE" : "BLOCK",
    root,
    adapter: adapterName,
    analyzer: adapterName === "typescript" ? "tsc" : basename(invocation.command),
    analyzer_version: probe.version,
    process_exit_code: result.status,
    passed,
    diagnostics,
    diagnostics_truncated: bounded.truncated,
    severity_counts: classifyDiagnostics(diagnostics),
    limitations: [
      "This adapter normalizes analyzer output; it does not prove runtime correctness or security.",
      "Dependencies are not downloaded, so an uncached dependency may make analysis unavailable.",
    ],
  };
}

function parseArguments(commandArguments) {
  const parsed = {
    path: ".",
    list: false,
    adapter: null,
    format: "markdown",
    allowProjectCode: false,
    importPath: null,
  };
  let positionals = 0;
  for (let index = 0; index < commandArguments.length; index += 1) {
    const value = commandArguments[index];
    if (["--adapter", "--format", "--import"].includes(value)) {
      const nextValue = commandArguments[index + 1];
      if (!nextValue || nextValue.startsWith("-")) throw new Error(`${value} requires a value`);
      if (value === "--adapter") parsed.adapter = nextValue;
      else if (value === "--import") parsed.importPath = nextValue;
      else parsed.format = nextValue;
      index += 1;
    } else if (value === "--list") {
      parsed.list = true;
    } else if (value === "--allow-project-code") {
      parsed.allowProjectCode = true;
    } else if (value.startsWith("-")) {
      throw new Error(`unknown option: ${value}`);
    } else if (positionals === 0) {
      parsed.path = value;
      positionals += 1;
    } else {
      throw new Error("too many positional arguments");
    }
  }
  if (!new Set(["json", "markdown"]).has(parsed.format)) throw new Error("unsupported format");
  if (parsed.adapter && !Object.hasOwn(ADAPTERS, parsed.adapter)) {
    throw new Error(`unsupported adapter: ${parsed.adapter}`);
  }
  return parsed;
}

function loadImportedEvidence(filePath) {
  let metadata;
  try {
    metadata = lstatSync(filePath);
  } catch {
    throw new Error(`cannot read imported evidence: ${filePath}`);
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error("imported evidence must be a regular file");
  }
  if (metadata.size > MAX_IMPORT_BYTES) {
    throw new Error(`evidence envelope exceeds ${MAX_IMPORT_BYTES} bytes`);
  }
  let payload;
  try {
    payload = JSON.parse(readFileSync(filePath, "utf8"));
  } catch {
    throw new Error("imported evidence is not valid JSON");
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("evidence envelope must be an object");
  }
  if (payload.schema_version !== "1.0") throw new Error("schema_version must be 1.0");
  const tool = payload.tool;
  if (!tool || typeof tool !== "object") throw new Error("tool identity is required");
  if (typeof tool.name !== "string" || !tool.name || tool.name === "ShipProof") {
    throw new Error("imported evidence cannot claim the ShipProof tool identity");
  }
  if (typeof tool.version !== "string" || !IMPORT_VERSION.test(tool.version)) {
    throw new Error("tool.version must be a semantic version");
  }
  if (typeof tool.command !== "string" || !tool.command) throw new Error("tool.command is required");
  if (!IMPORT_VERDICTS.has(payload.verdict)) throw new Error("verdict is missing or unsupported");
  if (!Array.isArray(payload.limitations) || payload.limitations.length === 0) {
    throw new Error("limitations must be a non-empty list");
  }
  if (typeof payload.target_digest !== "string" || !IMPORT_DIGEST.test(payload.target_digest)) {
    throw new Error("target_digest must be 64-character lowercase hex");
  }
  if (typeof payload.config_digest !== "string" || !IMPORT_DIGEST.test(payload.config_digest)) {
    throw new Error("config_digest must be 64-character lowercase hex");
  }
  if (typeof payload.captured_at !== "string" || !payload.captured_at) {
    throw new Error("captured_at is required");
  }
  const findingsIn = payload.findings || [];
  if (!Array.isArray(findingsIn) || findingsIn.length > 500) {
    throw new Error("findings must be a list of at most 500 items");
  }
  const findings = findingsIn.map((item, index) => {
    if (!item || typeof item !== "object") throw new Error(`findings[${index}] must be an object`);
    if (typeof item.original_rule_id !== "string" || !item.original_rule_id) {
      throw new Error(`findings[${index}].original_rule_id is required`);
    }
    if (!IMPORT_SEVERITIES.has(item.severity)) {
      throw new Error(`findings[${index}].severity is unsupported`);
    }
    if (typeof item.path !== "string" || !item.path) {
      throw new Error(`findings[${index}].path is required`);
    }
    const line = item.line ?? 1;
    if (!Number.isInteger(line) || line < 1) {
      throw new Error(`findings[${index}].line must be a positive integer`);
    }
    if (typeof item.message !== "string" || !item.message) {
      throw new Error(`findings[${index}].message is required`);
    }
    return {
      original_rule_id: item.original_rule_id,
      severity: item.severity,
      path: item.path,
      line,
      message: redactDiagnosticLine(item.message),
      imported: true,
      proof_level: "external",
    };
  });
  return {
    schema_version: "1.0",
    tool: { name: "ShipProof", version: VERSION, command: "import-external-evidence" },
    verdict: payload.verdict,
    imported_tool: { name: tool.name, version: tool.version, command: tool.command },
    target_digest: payload.target_digest,
    config_digest: payload.config_digest,
    captured_at: payload.captured_at,
    findings,
    limitations: [
      ...payload.limitations.map((item) => redactDiagnosticLine(String(item))),
      "Imported findings keep original_rule_id and are not native ShipProof proof.",
      "This adapter does not download, execute, or refresh the originating tool.",
    ],
  };
}

function renderMarkdown(report) {
  const lines = [
    `# ShipProof ${report.adapter} evidence: ${report.passed ? "PASS" : "BLOCK"}`,
    "",
    `Analyzer: \`${report.analyzer}\``,
    `Exit code: \`${report.process_exit_code}\``,
    "",
    "## Diagnostics",
    "",
    ...(report.diagnostics.length ? report.diagnostics.map((line) => `- ${line}`) : ["- None"]),
    "",
  ];
  return lines.join("\n");
}

export function runEvidenceCli(commandArguments) {
  try {
    const parsed = parseArguments(commandArguments);
    if (parsed.importPath) {
      if (parsed.list || parsed.adapter) {
        throw new Error("--import cannot be combined with --list or --adapter");
      }
      const report = loadImportedEvidence(parsed.importPath);
      console.log(parsed.format === "json" ? JSON.stringify(report, null, 2) : [
        `# ShipProof imported evidence: ${report.verdict}`,
        "",
        `Tool: \`${report.imported_tool.name}@${report.imported_tool.version}\``,
        `Findings: \`${report.findings.length}\``,
        "",
      ].join("\n"));
      return 0;
    }
    const adapters = discoverEvidenceAdapters(parsed.path, {
      allowProjectCode: parsed.allowProjectCode,
    });
    if (parsed.list) {
      if (parsed.format === "json") console.log(JSON.stringify(adapters, null, 2));
      else for (const adapter of adapters) {
        const state = adapter.approval_required
          ? "approval required"
          : adapter.detected && adapter.available ? "ready" : "unavailable";
        console.log(`${adapter.name}: ${state}`);
      }
      return 0;
    }
    const ready = adapters.filter((adapter) => adapter.detected && adapter.available);
    const adapterName = parsed.adapter || (ready.length === 1 ? ready[0].name : null);
    if (!adapterName) throw new Error("select one detected adapter with --adapter; use --list to inspect");
    const report = runEvidenceAdapter(parsed.path, adapterName, {
      allowProjectCode: parsed.allowProjectCode,
    });
    console.log(parsed.format === "json" ? JSON.stringify(report, null, 2) : renderMarkdown(report));
    return report.passed ? 0 : 1;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`shipproof: ${message}`);
    return 2;
  }
}

export const internals = {
  ADAPTERS,
  classifyDiagnostics,
  redactDiagnosticLine,
  loadImportedEvidence,
  bounds: {
    adapter_timeout_ms: ADAPTER_TIMEOUT_MS,
    max_buffer_bytes: ADAPTER_MAX_BUFFER_BYTES,
    max_diagnostic_lines: MAX_DIAGNOSTIC_LINES,
    max_diagnostic_line_chars: MAX_DIAGNOSTIC_LINE_CHARS,
  },
};
