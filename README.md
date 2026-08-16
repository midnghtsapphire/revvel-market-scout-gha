# GHA Workflow Guardian

[![Container CI/CD & Secure Release](https://github.com/midnghtsapphire/revvel-market-scout-gha/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/midnghtsapphire/revvel-market-scout-gha/actions/workflows/ci-cd.yml)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-GHA%20Workflow%20Guardian-brightgreen)](#)

Secure Docker action scanning GHA workflows for supply-chain risks, script injection vectors, and excessive permissions.

This action runs within a secure Docker container, scanning your repository workflows against complex supply chain attacks, command injection pathways, and unsafe permission grants.

## Features

- **Immutable Reference Inspection:** Requires external actions to use full commit SHAs and Docker actions to use SHA-256 digests.
- **Least-Privilege Auditing:** Detects missing token permissions, `write-all`, and named write scopes requiring review.
- **Script Injection Gate:** Detects direct `github.*` and reusable-workflow `inputs.*` interpolation in shell scripts.
- **Secret Handling Inspection:** Detects secrets interpolated directly into shell scripts instead of environment variables.
- **Severity Enforcement:** Fails at the configured LOW, MEDIUM, HIGH, or CRITICAL threshold.
- **Markdown Reporting:** Produces `validation-report.md` and a score from 0 to 100.

The repository's CI pipeline also scans this action's container image with Trivy. Image CVE scanning is separate from the workflow scanner executed by the Marketplace action.

## Quick Start (Usage Example)

Add this to your pull request workflow to check configurations securely:

```yaml
name: Security Pipeline

on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read # Restrict GITHUB_TOKEN
    steps:
      - name: Checkout Code
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Audit Repository Workflows
        uses: midnghtsapphire/revvel-market-scout-gha@v1
        with:
          scan-path: '.'
          severity-threshold: 'HIGH'
```

<!--doc_begin-->
### Inputs

| Input | Description | Default | Required |
| --- | --- | --- | --- |
| `scan-path` | Path of the directory to analyze | `.` | No |
| `severity-threshold` | Minimum severity level to trigger failure (LOW, MEDIUM, HIGH, CRITICAL) | `HIGH` | No |

### Outputs

| Output | Description |
| --- | --- |
| `report-path` | Path where the security audit report was saved |
| `score-summary` | Condensed metric representing compliance index (0-100) |
<!--doc_end-->

## Severity Rules

| Severity | Examples |
| --- | --- |
| CRITICAL | Direct GitHub/input expression in a script, `write-all`, invalid workflow YAML |
| HIGH | Mutable action reference, mutable Docker action, secret interpolated into a script |
| MEDIUM | Missing explicit permissions or a named write permission requiring review |

The action exits with a non-zero status when any finding meets or exceeds `severity-threshold`. Findings below the threshold remain visible as annotations and in the report.

## Local Development

```bash
python3 -m pip install --requirement requirements.txt
python3 -m unittest discover --start-directory tests --verbose
INPUT_SCAN_PATH=. INPUT_SEVERITY_THRESHOLD=HIGH python3 entrypoint.py
```

## Publishing to GitHub Marketplace

For full, semi-automated deployment to the GitHub Action Marketplace, execute:
```bash
chmod +x ./automated-release.sh
./automated-release.sh
```

This tags semantic versions correctly and triggers your pipeline. Ensure you have accepted the GitHub Marketplace Developer Agreement in your account settings prior to publication.

## License

MIT - See [LICENSE](LICENSE) for details.
