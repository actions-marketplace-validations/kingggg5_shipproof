import { spawnSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  openSync,
  closeSync,
  fstatSync,
  readFileSync,
  realpathSync,
  statSync,
} from "node:fs";
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
const MAX_IMPORT_DEPTH = 10;
const MAX_IMPORT_LINE = 10_000_000;
const IMPORT_DIGEST = /^[0-9a-f]{64}$/;
const IMPORT_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const IMPORT_VERDICTS = new Set(["PASS", "PASS_WITH_EVIDENCE", "CONDITIONAL", "WARN", "REVIEW", "BLOCK"]);
const IMPORT_SEVERITIES = new Set(["critical", "high", "medium", "low"]);
const IMPORT_TOP_FIELDS = new Set([
  "schema_version",
  "tool",
  "verdict",
  "limitations",
  "target_digest",
  "config_digest",
  "captured_at",
  "findings",
]);
const IMPORT_TOOL_FIELDS = new Set(["name", "version", "command"]);
const IMPORT_FINDING_FIELDS = new Set(["original_rule_id", "severity", "path", "line", "message"]);
const IMPORT_ABSOLUTE_PATH = /^(?:[A-Za-z]:[\\/]|\\\\|\/)/;

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
    expectTarget: null,
    expectConfig: null,
    maxAgeHours: null,
    clockSkewMinutes: 5,
    allowUnverified: false,
  };
  let positionals = 0;
  for (let index = 0; index < commandArguments.length; index += 1) {
    const value = commandArguments[index];
    if (["--adapter", "--format", "--import", "--expect-target", "--expect-config", "--max-age-hours", "--clock-skew-minutes"].includes(value)) {
      const nextValue = commandArguments[index + 1];
      if (!nextValue || nextValue.startsWith("-")) throw new Error(`${value} requires a value`);
      if (value === "--adapter") parsed.adapter = nextValue;
      else if (value === "--import") parsed.importPath = nextValue;
      else if (value === "--expect-target") parsed.expectTarget = nextValue;
      else if (value === "--expect-config") parsed.expectConfig = nextValue;
      else if (value === "--max-age-hours") {
        const hours = Number(nextValue);
        if (!Number.isFinite(hours) || hours < 0) {
          throw new Error("--max-age-hours must be a non-negative number");
        }
        parsed.maxAgeHours = hours;
      } else if (value === "--clock-skew-minutes") {
        const skew = Number(nextValue);
        if (!Number.isFinite(skew) || skew < 0) throw new Error("--clock-skew-minutes must be a non-negative number");
        parsed.clockSkewMinutes = skew;
      } else parsed.format = nextValue;
      index += 1;
    } else if (value === "--list") {
      parsed.list = true;
    } else if (value === "--allow-project-code") {
      parsed.allowProjectCode = true;
    } else if (value === "--allow-unverified") {
      parsed.allowUnverified = true;
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
  if (parsed.allowUnverified && !parsed.importPath) {
    throw new Error("--allow-unverified requires --import");
  }
  return parsed;
}

function throwOnDuplicateKeys(text) {
  const stack = [];
  let index = 0;
  const readString = () => {
    // Assumes text[index] === '"'; returns { value, end } with end past closing quote.
    let out = "";
    index += 1;
    while (index < text.length) {
      const ch = text[index];
      if (ch === "\\") {
        out += text.slice(index, index + 2);
        index += 2;
        continue;
      }
      if (ch === '"') {
        index += 1;
        return out;
      }
      out += ch;
      index += 1;
    }
    throw new Error("imported evidence is not valid JSON");
  };
  const skipWs = () => {
    while (index < text.length && /\s/.test(text[index])) index += 1;
  };
  const currentObject = () => {
    for (let depth = stack.length - 1; depth >= 0; depth -= 1) {
      if (stack[depth].type === "object") return stack[depth];
    }
    return null;
  };
  while (index < text.length) {
    skipWs();
    const ch = text[index];
    if (ch === undefined) break;
    if (ch === "{") {
      if (stack.length >= MAX_IMPORT_DEPTH) {
        throw new Error("evidence envelope exceeds nesting depth limit");
      }
      stack.push({ type: "object", keys: new Set(), expectKey: true });
      index += 1;
      continue;
    }
    if (ch === "[") {
      if (stack.length >= MAX_IMPORT_DEPTH) {
        throw new Error("evidence envelope exceeds nesting depth limit");
      }
      stack.push({ type: "array" });
      index += 1;
      continue;
    }
    if (ch === "}" || ch === "]") {
      stack.pop();
      index += 1;
      // After a value, parent object no longer expects a key.
      const parent = currentObject();
      if (parent) parent.expectKey = false;
      continue;
    }
    if (ch === '"') {
      const value = readString();
      skipWs();
      const obj = currentObject();
      if (text[index] === ":" && obj && stack[stack.length - 1]?.type === "object" && obj.expectKey) {
        if (obj.keys.has(value)) throw new Error(`duplicate field: ${value}`);
        obj.keys.add(value);
        obj.expectKey = false;
        index += 1;
        continue;
      }
      if (obj && stack[stack.length - 1]?.type === "object" && !obj.expectKey) {
        // A string value inside an object; next must be , or }.
      }
      continue;
    }
    if (ch === ",") {
      const obj = currentObject();
      if (obj && stack[stack.length - 1]?.type === "object") obj.expectKey = true;
      index += 1;
      continue;
    }
    if (ch === ":") {
      index += 1;
      continue;
    }
    index += 1;
  }
  if (stack.length !== 0) throw new Error("imported evidence is not valid JSON");
}

function checkImportDepth(value, depth = 0) {
  if (depth > MAX_IMPORT_DEPTH) throw new Error("evidence envelope exceeds nesting depth limit");
  if (Array.isArray(value)) {
    for (const item of value) checkImportDepth(item, depth + 1);
  } else if (value && typeof value === "object") {
    for (const item of Object.values(value)) checkImportDepth(item, depth + 1);
  }
}

function checkEvidencePath(pathText, field) {
  if (pathText.includes("\0")) throw new Error(`${field} must not contain NUL`);
  if (IMPORT_ABSOLUTE_PATH.test(pathText)) {
    throw new Error(`${field} must be repository-relative, not absolute`);
  }
  const segments = String(pathText).replace(/\\/g, "/").split("/").filter((s) => s !== "" && s !== ".");
  if (segments.length === 0 || segments.some((s) => s === "..")) {
    throw new Error(`${field} must stay inside the reviewed root`);
  }
  return pathText;
}

function parseImportTimestamp(value) {
  if (typeof value !== "string" || !value) throw new Error("captured_at is required");
  if (!/([zZ]|[+-]\d{2}:?\d{2})$/.test(value.trim())) {
    throw new Error("captured_at must include a timezone");
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) throw new Error("captured_at must be an ISO-8601 timestamp");
  return parsed;
}

function readImportBytes(filePath) {
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
  let descriptor = null;
  try {
    descriptor = openSync(filePath, "r");
    const opened = fstatSync(descriptor);
    const sameFile = opened.dev === metadata.dev
      && opened.ino === metadata.ino
      && opened.size === metadata.size
      && Number(opened.mtimeMs) === Number(metadata.mtimeMs);
    if (!sameFile && (opened.dev !== 0 || opened.ino !== 0)) {
      throw new Error("evidence envelope changed during open");
    }
    const text = readFileSync(descriptor, "utf8");
    const after = fstatSync(descriptor);
    if (Number(after.mtimeMs) !== Number(opened.mtimeMs) || after.size !== opened.size) {
      throw new Error("evidence envelope changed during read");
    }
    if (Buffer.byteLength(text, "utf8") > MAX_IMPORT_BYTES) {
      throw new Error(`evidence envelope exceeds ${MAX_IMPORT_BYTES} bytes`);
    }
    return text;
  } catch (error) {
    if (error instanceof Error && /evidence envelope/.test(error.message)) throw error;
    throw new Error(`cannot read imported evidence: ${filePath}`);
  } finally {
    if (descriptor !== null) {
      try {
        closeSync(descriptor);
      } catch {
        // ignore close errors; read result already decided
      }
    }
  }
}

function loadImportedEvidence(filePath, options = {}) {
  const {
    expectTarget = null,
    expectConfig = null,
    maxAgeHours = null,
    clockSkewMinutes = 5,
    allowUnverified = false,
    now = null,
  } = options || {};
  const text = readImportBytes(filePath);
  throwOnDuplicateKeys(text);
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new Error("imported evidence is not valid JSON");
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("evidence envelope must be an object");
  }
  for (const key of Object.keys(payload)) {
    if (!IMPORT_TOP_FIELDS.has(key)) throw new Error(`evidence envelope has unknown fields: ${key}`);
  }
  checkImportDepth(payload);
  if (payload.schema_version !== "1.0") throw new Error("schema_version must be 1.0");
  const tool = payload.tool;
  if (!tool || typeof tool !== "object" || Array.isArray(tool)) {
    throw new Error("tool identity is required");
  }
  for (const key of Object.keys(tool)) {
    if (!IMPORT_TOOL_FIELDS.has(key)) throw new Error(`tool has unknown fields: ${key}`);
  }
  if (typeof tool.name !== "string" || !tool.name || tool.name === "ShipProof") {
    throw new Error("imported evidence cannot claim the ShipProof tool identity");
  }
  if (typeof tool.version !== "string" || !IMPORT_VERSION.test(tool.version)) {
    throw new Error("tool.version must be a semantic version");
  }
  if (typeof tool.command !== "string" || !tool.command) throw new Error("tool.command is required");
  if (typeof payload.verdict !== "string" || !IMPORT_VERDICTS.has(payload.verdict)) {
    throw new Error("verdict is missing or unsupported");
  }
  if (!Array.isArray(payload.limitations) || payload.limitations.length === 0 || payload.limitations.length > 32) {
    throw new Error("limitations must be a non-empty list");
  }
  for (const item of payload.limitations) {
    if (typeof item !== "string" || !item || item.length > 1024) {
      throw new Error("limitations must be non-empty strings");
    }
  }
  if (typeof payload.target_digest !== "string" || !IMPORT_DIGEST.test(payload.target_digest)) {
    throw new Error("target_digest must be 64-character lowercase hex");
  }
  if (typeof payload.config_digest !== "string" || !IMPORT_DIGEST.test(payload.config_digest)) {
    throw new Error("config_digest must be 64-character lowercase hex");
  }
  const captured = parseImportTimestamp(payload.captured_at);
  const current = now instanceof Date && !Number.isNaN(now.getTime()) ? now : new Date();
  for (const [label, value] of [["clock-skew-minutes", clockSkewMinutes], ["max-age-hours", maxAgeHours]]) {
    if (value != null && (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1_000_000)) {
      throw new Error(`--${label} must be a finite non-negative number <= 1000000`);
    }
  }
  const skewMs = Number(clockSkewMinutes || 0) * 60_000;
  if (captured.getTime() > current.getTime() + skewMs) {
    throw new Error("captured_at is in the future beyond clock-skew allowance");
  }
  let stale = false;
  if (maxAgeHours !== null && maxAgeHours !== undefined) {
    const budget = Number(maxAgeHours);
    if (!Number.isFinite(budget) || budget < 0) {
      throw new Error("--max-age-hours must be a non-negative number");
    }
    stale = current.getTime() - captured.getTime() > budget * 3_600_000 + skewMs;
  }
  const findingsIn = payload.findings ?? [];
  if (!Array.isArray(findingsIn) || findingsIn.length > 500) {
    throw new Error("findings must be a list of at most 500 items");
  }
  const findings = findingsIn.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error(`findings[${index}] must be an object`);
    }
    for (const key of Object.keys(item)) {
      if (!IMPORT_FINDING_FIELDS.has(key)) {
        throw new Error(`findings[${index}] has unknown fields: ${key}`);
      }
    }
    if (typeof item.original_rule_id !== "string" || !item.original_rule_id || item.original_rule_id.length > 128) {
      throw new Error(`findings[${index}].original_rule_id is required`);
    }
    if (typeof item.severity !== "string" || !IMPORT_SEVERITIES.has(item.severity)) {
      throw new Error(`findings[${index}].severity is unsupported`);
    }
    if (typeof item.path !== "string" || !item.path || item.path.length > 512) {
      throw new Error(`findings[${index}].path is required`);
    }
    checkEvidencePath(item.path, `findings[${index}].path`);
    const line = item.line ?? 1;
    if (typeof line !== "number" || !Number.isInteger(line) || line < 1 || line > MAX_IMPORT_LINE) {
      throw new Error(`findings[${index}].line must be a positive integer`);
    }
    if (typeof item.message !== "string" || !item.message || item.message.length > 512) {
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
  for (const [label, expected] of [["target_digest", expectTarget], ["config_digest", expectConfig]]) {
    if (expected !== null && expected !== undefined && (typeof expected !== "string" || !IMPORT_DIGEST.test(expected))) {
      throw new Error(`expected ${label} must be 64-character lowercase hex`);
    }
  }
  const targetMatches = expectTarget === null || expectTarget === undefined || payload.target_digest === expectTarget;
  const configMatches = expectConfig === null || expectConfig === undefined || payload.config_digest === expectConfig;
  const identityMatches = Boolean(
    (expectTarget !== null && expectTarget !== undefined
      && expectConfig !== null && expectConfig !== undefined)
      && targetMatches && configMatches,
  );
  const reasons = [];
  if (!targetMatches) reasons.push("target_digest does not match the expected snapshot identity");
  if (!configMatches) reasons.push("config_digest does not match the expected effective-policy identity");
  if (stale) reasons.push("captured_at exceeds the caller max-age policy");
  if (expectTarget == null || expectConfig == null) {
    reasons.push("both expected target and config identities are required; digest claims are unverified");
  }
  const verified = Boolean(identityMatches && !stale);
  const mismatch = Boolean(!targetMatches || !configMatches);
  if ((mismatch || stale) && !allowUnverified) {
    throw new Error(`stale or foreign evidence: ${reasons.join("; ") || "evidence identity is unverified"}`);
  }
  const status = verified ? "verified" : "unverified";
  return {
    schema_version: "1.0",
    tool: { name: "ShipProof", version: VERSION, command: "import-external-evidence" },
    verdict: payload.verdict,
    imported_tool: { name: tool.name, version: tool.version, command: tool.command },
    target_digest: payload.target_digest,
    config_digest: payload.config_digest,
    captured_at: payload.captured_at,
    findings,
    identity_matches: identityMatches,
    authorship_verified: false,
    review_complete: false,
    assessment_verified: false,
    gate_eligible: false,
    resume_eligible: verified,
    verification: {
      status,
      reasons: reasons.length
        ? reasons
        : ["expected snapshot and policy identities match within freshness policy"],
      notes: [
        "Digest equality establishes identity with the reviewed bytes, not authorship or correctness.",
        "Imported findings are external hypotheses; they never become native ShipProof proof.",
      ],
    },
    limitations: [
      ...payload.limitations.map((item) => redactDiagnosticLine(String(item))),
      "Imported findings keep original_rule_id and are not native ShipProof proof.",
      "This adapter does not download, execute, or refresh the originating tool.",
      "Digest match does not prove the reviewer statement is true; authorship is unverified.",
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
      const report = loadImportedEvidence(parsed.importPath, {
        expectTarget: parsed.expectTarget,
        expectConfig: parsed.expectConfig,
        maxAgeHours: parsed.maxAgeHours,
        clockSkewMinutes: parsed.clockSkewMinutes,
        allowUnverified: parsed.allowUnverified,
      });
      console.log(parsed.format === "json" ? JSON.stringify(report, null, 2) : [
        `# ShipProof imported evidence: ${report.verdict}`,
        "",
        `Tool: \`${report.imported_tool.name}@${report.imported_tool.version}\``,
        `Findings: \`${report.findings.length}\``,
        `Verification: \`${report.verification.status}\``,
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
