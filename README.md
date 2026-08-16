# GHA Workflow Guardian

[![Container CI/CD & Secure Release](https://github.com/midnghtsapphire/revvel-market-scout-gha/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/midnghtsapphire/revvel-market-scout-gha/actions/workflows/ci-cd.yml)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-GHA%20Workflow%20Guardian-brightgreen)](#)

Secure composite action scanning GHA workflows for supply-chain risks, script injection vectors, and excessive permissions.

This action runs within a secure Docker container, scanning your repository workflows against complex supply chain attacks, command injection pathways, and unsafe permission grants.

## Features

- **SHA Version Pinning Inspection:** Identifies unpinned or insecure action references.
- **Least-Privilege Auditing:** Enforces restrictive default scopes on the GITHUB_TOKEN.
- **Script Injection Gate:** Mitigates risk of dynamic expressions executing untrusted code on your runners.
- **CVE Static Scanning Integration:** Leverages pre-push security gates.

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

## Publishing to GitHub Marketplace

For full, semi-automated deployment to the GitHub Action Marketplace, execute:
```bash
chmod +x ./automated-release.sh
./automated-release.sh
```

This tags semantic versions correctly and triggers your pipeline. Ensure you have accepted the GitHub Marketplace Developer Agreement in your account settings prior to publication.

## License

MIT - See [LICENSE](LICENSE) for details.
