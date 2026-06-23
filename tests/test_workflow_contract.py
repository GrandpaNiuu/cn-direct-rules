from __future__ import annotations

import unittest
from pathlib import Path

from scripts.ruleset import ROOT


class WorkflowContractTests(unittest.TestCase):
    def test_audit_workflows_do_not_bypass_main_update_pipeline(self) -> None:
        workflows = ROOT / ".github" / "workflows"
        forbidden = {
            "rir-audit.yml",
            "bgp-origin-audit.yml",
        }
        present = {path.name for path in workflows.glob("*.yml")}
        self.assertFalse(
            forbidden & present,
            "audit sources must be integrated through config/sources.json and scripts/update_sources.py, "
            "not through standalone workflows",
        )

    def test_main_update_pipeline_is_the_rule_generation_entrypoint(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "update.yml").read_text(encoding="utf-8")
        self.assertIn("python scripts/update_sources.py", workflow)
        self.assertIn("python scripts/build.py", workflow)
        self.assertIn("python scripts/validate.py", workflow)


if __name__ == "__main__":
    unittest.main()
