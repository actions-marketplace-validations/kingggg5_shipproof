from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "ai_inventory.py"
SPEC = importlib.util.spec_from_file_location("ai_inventory", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load AI inventory")
ai_inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ai_inventory
SPEC.loader.exec_module(ai_inventory)


class AIInventoryTests(unittest.TestCase):
    def test_skill_and_mcp_fixtures_split_declared_observed_and_redact(self):
        payload = ai_inventory.inventory(ROOT / "fixtures" / "ai-inventory")
        paths = {item["path"]: item for item in payload["components"]}
        self.assertIn("skill-package/SKILL.md", paths)
        skill = paths["skill-package/SKILL.md"]
        self.assertEqual(skill["declared"].get("name"), "sample-inventory-skill")
        self.assertIn("filesystem", skill["observed_static"])
        mcp_path = next(path for path in paths if path.endswith("mcp.json"))
        mcp = paths[mcp_path]
        self.assertEqual(mcp["kind"], "mcp_config")
        self.assertNotIn("sk-exampletestvalue-not-a-real-secret", str(payload))

    def test_redteam_lab_is_inventory_only_and_never_claims_safety(self):
        payload = ai_inventory.inventory(ROOT / "fixtures" / "labs" / "agent-redteam")
        self.assertGreaterEqual(payload["summary"]["components"], 2)
        joined = str(payload)
        self.assertNotIn("ghp_exampletestvalue_not_real", joined)
        kinds = {item["kind"] for item in payload["components"]}
        self.assertEqual(kinds, {"skill", "mcp_config"})
        self.assertTrue(
            any("unknown" in item.lower() for item in payload["limitations"]),
            payload["limitations"],
        )


if __name__ == "__main__":
    unittest.main()
