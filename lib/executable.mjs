import { lstatSync, realpathSync, statSync } from "node:fs";
import { delimiter, extname, isAbsolute, join, relative, resolve, sep } from "node:path";

function isInside(root, candidate) {
  const relativePath = relative(root, candidate);
  return relativePath === ""
    || (relativePath !== ".." && !relativePath.startsWith(`..${sep}`) && !isAbsolute(relativePath));
}

function pathEnvironment(environment) {
  return environment.PATH ?? environment.Path ?? environment.path ?? "";
}

function candidateNames(command) {
  if (process.platform !== "win32" || extname(command)) return [command];
  // Analyzer and runtime entry points are native executables. Do not resolve
  // .cmd/.bat files from an untrusted PATH: shell wrappers are a code-exec
  // boundary and are not needed for the supported Go/Rust/Python binaries.
  return [command, `${command}.exe`, `${command}.com`];
}

function validateCandidate(
  candidate,
  repositoryRoot,
  { allowInsideRoot = false, lexicalRoot = repositoryRoot } = {},
) {
  const absolute = resolve(candidate);
  // Check the lexical path before realpath. A repository-controlled symlink
  // directory (for example `node_modules/.bin -> external`) would otherwise
  // canonicalize outside the root and look like a trusted host PATH entry.
  // Only an explicit operator opt-in may resolve a path lexically inside the
  // repository; the normal analyzer/runtime path must reject it outright.
  if (
    !allowInsideRoot
    && (isInside(lexicalRoot, absolute) || isInside(repositoryRoot, absolute))
  ) return null;
  try {
    const lexical = lstatSync(absolute);
    // Host PATH entries such as `python3` are routinely symlinks. Reject only
    // non-file lexical types here; follow the link, then require the canonical
    // target to be a regular executable outside the repository.
    if (!lexical.isFile() && !lexical.isSymbolicLink()) return null;
    const real = realpathSync.native(absolute);
    if (!allowInsideRoot && isInside(repositoryRoot, real)) return null;
    const metadata = statSync(real);
    if (!metadata.isFile()) return null;
    if (process.platform !== "win32" && (metadata.mode & 0o111) === 0) return null;
    return real;
  } catch {
    return null;
  }
}

/**
 * Resolve a command without consulting the current working directory.
 * Relative PATH entries are deliberately ignored because they let a checked
 * out `python`, `go`, or `cargo` shadow the host tool. The returned path is
 * canonical and never points into the scan root unless the caller explicitly
 * opts in for a user-provided executable.
 */
export function resolveTrustedExecutable(
  command,
  { root = process.cwd(), environment = process.env, allowInsideRoot = false } = {},
) {
  if (typeof command !== "string" || !command || /[\0\r\n]/.test(command)) return null;
  const repositoryPath = resolve(root);
  // Windows APIs may return an 8.3 short path for the root while realpath on
  // a candidate returns the long spelling. Canonicalize both sides before the
  // containment check so a repository-local implant cannot evade it through
  // path-alias differences.
  const repositoryRoot = (() => {
    try {
      return realpathSync.native(repositoryPath);
    } catch {
      return repositoryPath;
    }
  })();
  if (isAbsolute(command) || command.includes("/") || command.includes("\\")) {
    return isAbsolute(command)
      ? validateCandidate(command, repositoryRoot, {
        allowInsideRoot,
        lexicalRoot: repositoryPath,
      })
      : null;
  }
  const pathEntries = String(pathEnvironment(environment))
    .split(delimiter)
    .filter((entry) => entry && isAbsolute(entry));
  const seen = new Set();
  for (const directory of pathEntries) {
    for (const name of candidateNames(command)) {
      const candidate = join(directory, name);
      const resolved = validateCandidate(candidate, repositoryRoot, {
        allowInsideRoot: false,
        lexicalRoot: repositoryPath,
      });
      if (resolved && !seen.has(resolved)) {
        seen.add(resolved);
        return resolved;
      }
    }
  }
  return null;
}

export const internals = { isInside, candidateNames, pathEnvironment };
