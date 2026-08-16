import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml


SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_DEDUCTIONS = {"LOW": 3, "MEDIUM": 8, "HIGH": 15, "CRITICAL": 25}
WORKFLOW_SUFFIXES = {".yml", ".yaml"}
ACTION_USE_PATTERN = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*['\"]?([^'\"\s#]+)")
EXPRESSION_PATTERN = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
SHA_PATTERN = re.compile(r"[0-9a-fA-F]{40}")
DOCKER_DIGEST_PATTERN = re.compile(r".+@sha256:[0-9a-fA-F]{64}")


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    path: Path
    line: int
    message: str


def discover_workflows(scan_path: Path) -> list[Path]:
    if scan_path.is_file():
        return [scan_path] if scan_path.suffix.lower() in WORKFLOW_SUFFIXES else []
    if not scan_path.is_dir():
        return []

    standard_directory = scan_path / ".github" / "workflows"
    search_root = standard_directory if standard_directory.is_dir() else scan_path
    return sorted(
        path
        for path in search_root.rglob("*")
        if path.is_file() and path.suffix.lower() in WORKFLOW_SUFFIXES
    )


def _run_script_lines(lines: list[str]) -> Iterable[tuple[int, str]]:
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(\s*)(?:-\s*)?run\s*:\s*(.*)$", line)
        if not match:
            index += 1
            continue

        indentation = len(match.group(1))
        value = match.group(2).strip()
        if value and not value.startswith(("|", ">")):
            yield index + 1, value
            index += 1
            continue

        index += 1
        while index < len(lines):
            script_line = lines[index]
            if script_line.strip() and len(script_line) - len(script_line.lstrip()) <= indentation:
                break
            yield index + 1, script_line
            index += 1


def _permission_findings(document: dict[Any, Any], path: Path) -> list[Finding]:
    findings: list[Finding] = []
    global_permissions = document.get("permissions")
    jobs = document.get("jobs")

    if global_permissions is None:
        job_definitions = jobs if isinstance(jobs, dict) else {}
        jobs_without_permissions = [
            str(name)
            for name, job in job_definitions.items()
            if not isinstance(job, dict) or "permissions" not in job
        ]
        if not job_definitions or jobs_without_permissions:
            findings.append(
                Finding(
                    "MISSING_PERMISSIONS",
                    "MEDIUM",
                    path,
                    1,
                    "Set explicit read-only workflow or job permissions for GITHUB_TOKEN.",
                )
            )

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "permissions":
                    inspect_permissions(child)
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    def inspect_permissions(value: Any) -> None:
        if isinstance(value, str) and value.lower() == "write-all":
            findings.append(
                Finding(
                    "WRITE_ALL_PERMISSIONS",
                    "CRITICAL",
                    path,
                    1,
                    "Replace write-all with the minimum required named permissions.",
                )
            )
        elif isinstance(value, dict):
            for scope, access in value.items():
                if isinstance(access, str) and access.lower() == "write":
                    findings.append(
                        Finding(
                            "WRITE_PERMISSION",
                            "MEDIUM",
                            path,
                            1,
                            f"Review whether '{scope}: write' is required for this job.",
                        )
                    )

    walk(document)
    return findings


def scan_workflow(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return [Finding("UNREADABLE_WORKFLOW", "CRITICAL", path, 1, str(error))]

    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError as error:
        line = getattr(getattr(error, "problem_mark", None), "line", 0) + 1
        return [Finding("INVALID_YAML", "CRITICAL", path, line, str(error).splitlines()[0])]

    if not isinstance(document, dict):
        return [
            Finding(
                "INVALID_WORKFLOW",
                "CRITICAL",
                path,
                1,
                "Workflow document must contain a YAML mapping.",
            )
        ]

    lines = content.splitlines()
    for line_number, line in enumerate(lines, start=1):
        match = ACTION_USE_PATTERN.match(line)
        if not match:
            continue
        action_reference = match.group(1)
        if action_reference.startswith("./"):
            continue
        if action_reference.startswith("docker://"):
            image_reference = action_reference.removeprefix("docker://")
            if not DOCKER_DIGEST_PATTERN.fullmatch(image_reference):
                findings.append(
                    Finding(
                        "UNPINNED_DOCKER_ACTION",
                        "HIGH",
                        path,
                        line_number,
                        f"Pin '{action_reference}' to an immutable sha256 digest.",
                    )
                )
            continue

        reference = action_reference.rpartition("@")[2]
        if not SHA_PATTERN.fullmatch(reference):
            findings.append(
                Finding(
                    "UNPINNED_ACTION",
                    "HIGH",
                    path,
                    line_number,
                    f"Pin '{action_reference}' to a full 40-character commit SHA.",
                )
            )

    for line_number, script_line in _run_script_lines(lines):
        for expression in EXPRESSION_PATTERN.findall(script_line):
            normalized_expression = expression.lower()
            if "secrets." in normalized_expression or "github.token" in normalized_expression:
                findings.append(
                    Finding(
                        "SECRET_IN_SCRIPT",
                        "HIGH",
                        path,
                        line_number,
                        "Pass secrets through a step-level environment variable instead of direct script interpolation.",
                    )
                )
            elif "github." in normalized_expression or "inputs." in normalized_expression:
                findings.append(
                    Finding(
                        "SCRIPT_INJECTION",
                        "CRITICAL",
                        path,
                        line_number,
                        "Move GitHub or workflow input expressions into an environment variable before using them in a script.",
                    )
                )

    findings.extend(_permission_findings(document, path))
    return findings


def scan(scan_path: Path) -> tuple[list[Path], list[Finding]]:
    if not scan_path.exists():
        return [], [
            Finding("SCAN_PATH_NOT_FOUND", "CRITICAL", scan_path, 1, "Scan path does not exist.")
        ]

    workflows = discover_workflows(scan_path)
    if not workflows:
        return [], [
            Finding("NO_WORKFLOWS", "MEDIUM", scan_path, 1, "No YAML workflow files were found.")
        ]

    findings = [finding for workflow in workflows for finding in scan_workflow(workflow)]
    findings.sort(
        key=lambda finding: (
            -SEVERITY_LEVELS[finding.severity],
            str(finding.path),
            finding.line,
            finding.rule,
        )
    )
    return workflows, findings


def calculate_score(findings: Iterable[Finding]) -> int:
    return max(0, 100 - sum(SEVERITY_DEDUCTIONS[finding.severity] for finding in findings))


def gate_failed(findings: Iterable[Finding], threshold: str) -> bool:
    threshold_level = SEVERITY_LEVELS[threshold]
    return any(SEVERITY_LEVELS[finding.severity] >= threshold_level for finding in findings)


def _display_path(path: Path, scan_path: Path) -> str:
    base_path = scan_path if scan_path.is_dir() else scan_path.parent
    try:
        return str(path.resolve().relative_to(base_path.resolve()))
    except ValueError:
        return str(path)


def write_report(
    report_path: Path,
    scan_path: Path,
    workflows: list[Path],
    findings: list[Finding],
    threshold: str,
) -> int:
    score = calculate_score(findings)
    counts = Counter(finding.severity for finding in findings)
    status = "FAIL" if gate_failed(findings, threshold) else "PASS"
    report_lines = [
        "# GHA Workflow Guardian Report",
        "",
        f"- **Status:** {status}",
        f"- **Score:** {score}/100",
        f"- **Threshold:** {threshold}",
        f"- **Workflows scanned:** {len(workflows)}",
        "- **Findings:** "
        + ", ".join(f"{severity}={counts[severity]}" for severity in reversed(SEVERITY_LEVELS)),
        "",
        "## Findings",
        "",
    ]
    if findings:
        report_lines.extend(
            f"- **{finding.severity} {finding.rule}** "
            f"`{_display_path(finding.path, scan_path)}:{finding.line}` - {finding.message}"
            for finding in findings
        )
    else:
        report_lines.append("No security findings detected.")
    report_lines.append("")
    report_path.write_text("\n".join(report_lines), encoding="utf-8")
    return score


def _emit_annotation(finding: Finding, scan_path: Path) -> None:
    annotation_level = "error" if finding.severity in {"HIGH", "CRITICAL"} else "warning"
    message = finding.message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(
        f"::{annotation_level} file={_display_path(finding.path, scan_path)},"
        f"line={finding.line},title={finding.severity} {finding.rule}::{message}"
    )


def _get_input(name: str, default: str) -> str:
    docker_name = f"INPUT_{name}"
    shell_name = docker_name.replace("-", "_")
    return os.getenv(docker_name, os.getenv(shell_name, default))


def main() -> int:
    threshold = _get_input("SEVERITY-THRESHOLD", "HIGH").strip().upper()
    if threshold not in SEVERITY_LEVELS:
        print(f"::error::Invalid severity threshold '{threshold}'.")
        return 2

    workspace = Path(os.getenv("GITHUB_WORKSPACE", os.getcwd()))
    configured_path = Path(_get_input("SCAN-PATH", "."))
    scan_path = configured_path if configured_path.is_absolute() else workspace / configured_path
    report_path = workspace / "validation-report.md"

    print("Executing GHA Workflow Guardian security validation action...")
    print(f"Auditing workflow path: {scan_path}")
    print(f"Enforcing severity gate: {threshold}")

    workflows, findings = scan(scan_path)
    score = write_report(report_path, scan_path, workflows, findings, threshold)
    for finding in findings:
        _emit_annotation(finding, scan_path)

    output_path = os.getenv("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as output_file:
            output_file.write(f"report-path={report_path}\n")
            output_file.write(f"score-summary={score}\n")

    if gate_failed(findings, threshold):
        print(f"FAILED: {len(findings)} finding(s) detected; score {score}/100.")
        return 1

    print(f"SUCCESS: {len(workflows)} workflow(s) scanned; score {score}/100.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
