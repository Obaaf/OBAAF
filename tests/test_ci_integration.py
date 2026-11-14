"""Consumers must receive the same located findings even when the gate fails."""
import json
from pathlib import Path
import unittest

from helpers import ROOT, TempDir, run_cli


class CiReportContractTest(unittest.TestCase):
    def test_failing_gate_writes_equivalent_located_findings_in_both_formats(self):
        workflow = ROOT / "tests/fixtures/workflows/risky/agent-lane-misspelled.yml"
        with TempDir() as directory:
            reports = {}
            for fmt in ("json", "sarif"):
                path = Path(directory) / ("report." + fmt)
                status, _, err = run_cli("check", str(workflow), "--fail-on", "medium",
                                         "--format", fmt, "--output", str(path))
                self.assertEqual(status, 1, err)
                reports[fmt] = json.loads(path.read_text(encoding="utf-8"))

        findings = sorted((f["rule"], f["path"], f["line"]) for f in reports["json"]["findings"])
        self.assertIn(("OBAAF-CFG-001", workflow.name, 14), findings)
        results = []
        for result in reports["sarif"]["runs"][0]["results"]:
            location = result["locations"][0]["physicalLocation"]
            results.append((result["ruleId"], location["artifactLocation"]["uri"],
                            location["region"]["startLine"]))
        self.assertEqual(sorted(results), findings)
