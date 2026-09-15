import { spawnSync } from "node:child_process";

import { resolveTrustedExecutable } from "./executable.mjs";

let cachedRuntime = null;
let runtimeCachePopulated = false;
let runtimeCacheKey = "";

export function isSupportedPythonVersion(version) {
  const match = /Python\s+(\d+)\.(\d+)/.exec(version || "");
  return Boolean(match)
    && (Number(match[1]) > 3 || (Number(match[1]) === 3 && Number(match[2]) >= 10));
}

function readExecutableVersion(command, argumentPrefix, rootPath, environment) {
  const result = spawnSync(command, [...argumentPrefix, "--version"], {
    cwd: rootPath,
    env: environment,
    encoding: "utf8",
    maxBuffer: 64 * 1024,
    shell: false,
    timeout: 3_000,
    windowsHide: true,
  });
  if (result.status !== 0 || result.signal || result.error) return null;
  return `${result.stdout || ""}${result.stderr || ""}`.trim();
}

/**
 * Detect a Python 3.10+ runtime once per process. The result is cached because
 * gates and MCP tools used to re-probe (up to four spawns) on every call.
 * Returns null when no supported runtime is available.
 */
export function detectPythonRuntime({
  refresh = false,
  rootPath = process.cwd(),
  environment = process.env,
} = {}) {
  const cacheKey = `${rootPath}\u0000${environment.SHIPPROOF_PYTHON || ""}\u0000${environment.PATH || environment.Path || ""}`;
  if (!refresh && runtimeCachePopulated && runtimeCacheKey === cacheKey) return cachedRuntime;
  const candidates = [];
  if (environment.SHIPPROOF_PYTHON) candidates.push([environment.SHIPPROOF_PYTHON, []]);
  if (process.platform === "win32") candidates.push(["py", ["-3"]]);
  candidates.push(["python3", []], ["python", []]);
  for (const [requestedCommand, argumentPrefix] of candidates) {
    const command = resolveTrustedExecutable(requestedCommand, {
      root: rootPath,
      environment,
      // SHIPPROOF_PYTHON is an explicit operator choice, but it must still be
      // an absolute path. A bare value would reintroduce PATH/cwd shadowing.
      allowInsideRoot: Boolean(environment.SHIPPROOF_PYTHON && requestedCommand === environment.SHIPPROOF_PYTHON),
    });
    if (!command) continue;
    const version = readExecutableVersion(command, argumentPrefix, rootPath, environment);
    if (version && isSupportedPythonVersion(version)) {
      cachedRuntime = { command, argumentPrefix, version };
      runtimeCachePopulated = true;
      runtimeCacheKey = cacheKey;
      return cachedRuntime;
    }
  }
  cachedRuntime = null;
  runtimeCachePopulated = true;
  runtimeCacheKey = cacheKey;
  return cachedRuntime;
}

export const internals = {
  resetRuntimeCache() {
    cachedRuntime = null;
    runtimeCachePopulated = false;
    runtimeCacheKey = "";
  },
};
