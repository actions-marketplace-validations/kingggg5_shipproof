import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { buildPolicyGates, loadPolicy, parsePolicyText, validatePolicy } from "../../lib/policy.mjs";
import { internals } from "../../lib/cli.mjs";

test("parses and validates the repository policy without a YAML runtime", () => {
  const { path, policy } = loadPolicy(internals.PACKAGE_ROOT);
  assert.equal(path, join(internals.PACKAGE_ROOT, ".shipproof.yml"));
  assert.equal(policy.version, 1);
  assert.equal(policy.security.fail_on, "high");
  assert.deepEqual(policy.scan.exclude, ["examples/demo-api/fixtures/**"]);
});

test("builds only fixed allowlisted gate commands", () => {
  const { policy } = loadPolicy(internals.PACKAGE_ROOT);
  const gates = buildPolicyGates(internals.PACKAGE_ROOT, policy);
  assert.deepEqual(gates.map((gate) => gate.command), ["scan", "budget", "capacity"]);
  assert.ok(gates[0].argumentsList.includes("--exclude"));
  assert.ok(gates.every((gate) => !gate.argumentsList.some((value) => value.includes(";"))));
});

test("rejects unsupported YAML features, duplicate keys, and unknown policy keys", () => {
  assert.throws(() => parsePolicyText("version: 1\nscan: &defaults\n  path: .\n"), /unsupported YAML/);
  assert.throws(() => parsePolicyText("version: 1\nversion: 1\n"), /duplicate key/);
  assert.throws(() => validatePolicy({ version: 1, command: "curl example.test" }), /unknown policy keys/);
});

test("rejects paths outside the repository", () => {
  assert.throws(() => loadPolicy(internals.PACKAGE_ROOT, "../.shipproof.yml"), /invalid policy file/);
  const policy = validatePolicy({ version: 1, scan: { path: ".." } });
  assert.throws(() => buildPolicyGates(internals.PACKAGE_ROOT, policy), /requested path/);
});

test("repository policy coverage gate accepts only a boolean (check remains fail-closed)", () => {
  for (const enabled of [undefined, false, true]) {
    const policy = validatePolicy({ version: 1, security: { fail_on_incomplete: enabled } });
    const [gate] = buildPolicyGates(internals.PACKAGE_ROOT, policy);
    assert.equal(gate.argumentsList.includes("--fail-on-incomplete"), enabled === true);
  }
  for (const invalid of ["false", "true", 0, 1, null, [], {}]) {
    assert.throws(
      () => validatePolicy({ version: 1, security: { fail_on_incomplete: invalid } }),
      /fail_on_incomplete must be a boolean/,
    );
  }
  const parsed = parsePolicyText("version: 1\nsecurity:\n  fail_on_incomplete: true\n");
  assert.equal(validatePolicy(parsed).security.fail_on_incomplete, true);
});

test("allowMissing permits only an absent policy, not a wrong path type", () => {
  const root = mkdtempSync(join(tmpdir(), "shipproof-policy-"));
  try {
    assert.equal(loadPolicy(root, ".shipproof.yml", { allowMissing: true }), null);
    mkdirSync(join(root, ".shipproof.yml"));
    assert.throws(
      () => loadPolicy(root, ".shipproof.yml", { allowMissing: true }),
      /requested path is not a file/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("scan profile and proof floor are explicit policy keys", () => {
  const policy = validatePolicy({
    version: 1,
    scan: { profile: "library" },
    security: { block_min_proof: "L2" },
  });
  assert.equal(policy.scan.profile, "library");
  assert.equal(policy.security.block_min_proof, "L2");
  const [gate] = buildPolicyGates(internals.PACKAGE_ROOT, policy);
  assert.ok(gate.argumentsList.includes("--scan-profile"));
  assert.ok(gate.argumentsList.includes("library"));
  assert.ok(gate.argumentsList.includes("--block-min-proof"));
  assert.ok(gate.argumentsList.includes("L2"));
  assert.throws(
    () => validatePolicy({ version: 1, scan: { profile: "service" } }),
    /scan.profile must be auto, application, or library/,
  );
  assert.throws(
    () => validatePolicy({ version: 1, security: { block_min_proof: "L3" } }),
    /security.block_min_proof must be L0, L1, or L2/,
  );
});

test("capacity accepts reviewed numeric inputs and rejects unknown fields", () => {
  const policy = validatePolicy({
    version: 1,
    capacity: { target_users: 10_000, inputs: { headroom: 1.5 } },
  });
  assert.equal(policy.capacity.target_users, 10_000);
  assert.throws(
    () => validatePolicy({ version: 1, capacity: { target_users: 1, inputs: { shell: "rm" } } }),
    /unknown capacity.inputs keys/,
  );
});
