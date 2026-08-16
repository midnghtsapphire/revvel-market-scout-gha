import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from entrypoint import (
    calculate_score,
    gate_failed,
    main,
    scan,
    scan_workflow,
    write_report,
)


PINNED_CHECKOUT = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.workflow_directory = self.root / ".github" / "workflows"
        self.workflow_directory.mkdir(parents=True)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def write_workflow(self, content):
        workflow = self.workflow_directory / "test.yml"
        workflow.write_text(content, encoding="utf-8")
        return workflow

    def test_secure_workflow_passes(self):
        self.write_workflow(
            f"""name: Safe
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: {PINNED_CHECKOUT}
      - run: echo safe
"""
        )

        workflows, findings = scan(self.root)

        self.assertEqual(len(workflows), 1)
        self.assertEqual(findings, [])
        self.assertFalse(gate_failed(findings, "HIGH"))

    def test_unpinned_action_fails_high_gate(self):
        workflow = self.write_workflow(
            """name: Unpinned
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        )

        findings = scan_workflow(workflow)

        self.assertIn("UNPINNED_ACTION", {finding.rule for finding in findings})
        self.assertTrue(gate_failed(findings, "HIGH"))

    def test_direct_context_and_secret_interpolation_are_flagged(self):
        workflow = self.write_workflow(
            """name: Injection
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.event.pull_request.title }}"
          curl -H "Authorization: ${{ secrets.API_TOKEN }}" example.com
"""
        )

        findings = scan_workflow(workflow)
        rules = {finding.rule for finding in findings}

        self.assertIn("SCRIPT_INJECTION", rules)
        self.assertIn("SECRET_IN_SCRIPT", rules)

    def test_write_all_is_critical(self):
        workflow = self.write_workflow(
            """name: Excessive
on: push
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo unsafe
"""
        )

        findings = scan_workflow(workflow)

        self.assertIn("WRITE_ALL_PERMISSIONS", {finding.rule for finding in findings})
        self.assertTrue(gate_failed(findings, "CRITICAL"))

    def test_invalid_yaml_is_critical(self):
        workflow = self.write_workflow("jobs:\n  test: [\n")

        findings = scan_workflow(workflow)

        self.assertEqual(findings[0].rule, "INVALID_YAML")
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_report_contains_score_and_findings(self):
        workflow = self.write_workflow(
            """name: Unpinned
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        )
        workflows, findings = scan(self.root)
        report_path = self.root / "validation-report.md"

        score = write_report(report_path, self.root, workflows, findings, "HIGH")

        report = report_path.read_text(encoding="utf-8")
        self.assertEqual(score, calculate_score(findings))
        self.assertIn("**Status:** FAIL", report)
        self.assertIn("UNPINNED_ACTION", report)

    def test_main_writes_outputs_and_returns_gate_status(self):
        self.write_workflow(
            """name: Missing permissions
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo review
"""
        )
        output_path = self.root / "github-output.txt"
        environment = {
            "GITHUB_WORKSPACE": str(self.root),
            "GITHUB_OUTPUT": str(output_path),
            "INPUT_SCAN-PATH": ".",
            "INPUT_SEVERITY_THRESHOLD": "MEDIUM",
        }

        with patch.dict(os.environ, environment, clear=True):
            result = main()

        self.assertEqual(result, 1)
        outputs = output_path.read_text(encoding="utf-8")
        self.assertIn("report-path=", outputs)
        self.assertIn("score-summary=92", outputs)


if __name__ == "__main__":
    unittest.main()