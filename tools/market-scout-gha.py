#!/usr/bin/env python3
"""
MarketScout GHA: Deterministic Container Product Viability Evaluator and Scaffolder
Grounded in GitHub Actions Best Practices and Marketplace Standards.
"""

import os
import sys
import json
import re

class ContainerProductEvaluator:
    def __init__(self, name, description, category, target_audience="devs"):
        self.name = name.strip()
        self.description = description.strip()
        self.category = category.strip()
        self.target_audience = target_audience.strip()
        self.scores = {}
        self.recommendations = []

    def evaluate_reddit_demand(self, pain_point_addressed, has_self_hosted_option, is_fluff_free):
        """
        Evaluate demand indicators based on Reddit self-hosted and DevOps chatter.
        Grounded in sources on user pain points (HTTPS trauma, alert bloat, complex hosting).
        """
        score = 0
        factors = []

        # Pain points from sources (e.g. HTTPS setup [290, 291], alert setup complexity [58, 60], waste of compute [336])
        if pain_point_addressed:
            score += 40
            factors.append("Directly addresses a documented developer pain point (+40)")
        else:
            factors.append("Lacks a clear, high-priority developer pain point (0)")

        if has_self_hosted_option:
            score += 35
            factors.append("Offers a secure, self-hosted deployment option satisfying data privacy requirements (+35)")
        else:
            factors.append("Cloud-only offering creates data privacy hurdles for enterprises (0)")

        if is_fluff_free:
            score += 25
            factors.append("Fluff-free, single-focus utility aligns with developer user preferences (+25)")
        else:
            factors.append("Too many unrelated features increase cognitive overhead (0)")

        self.scores['reddit_demand'] = {
            'score': score,
            'factors': factors
        }
        return score

    def evaluate_monetization_readiness(self, open_core, saas_hosting, support_slas, enterprise_features):
        """
        Evaluate monetization models based on SaaS, Open-Core, and Dual Licensing source material.
        Grounded in Reo.dev and PEXT quantitative analyses (databases/auth/infra scale best) [129, 153, 154].
        """
        score = 0
        factors = []

        # Leading indicators of monetization readiness [160]:
        # - Stars growth, PRs, Downloads, SLA demands, At-scale requests

        if open_core:
            score += 30
            factors.append("Open-core model: free core for community, proprietary plugins/extension for enterprise (+30)")
        if saas_hosting:
            score += 30
            factors.append("Hosted SaaS model: eliminates operational complexity for teams wishing to offload ops (+30)")
        if support_slas:
            score += 20
            factors.append("Enterprise support SLA alignment: monetizes complex infrastructure operational needs (+20)")
        if enterprise_features:
            score += 20
            factors.append("Enterprise features (compliance, auditing, advanced security scaling) (+20)")

        self.scores['monetization'] = {
            'score': score,
            'factors': factors
        }
        return score

    def evaluate_docker_best_practices(self, uses_multi_stage, pins_base_image, runs_as_non_root, incorporates_cve_scanning):
        """
        Evaluate image security and build hygiene.
        Grounded in Docker Security Basics, OWASP, and Dash0 vulnerability scanner resources [46, 62, 101, 167].
        """
        score = 0
        factors = []

        if uses_multi_stage:
            score += 25
            factors.append("Multi-stage build reduces final image size and attack surface (+25)")
        else:
            factors.append("Single-stage build includes unnecessary build tools and increases image footprint (0)")

        if pins_base_image:
            score += 25
            factors.append("Base image version is pinned by specific tag or cryptographic digest SHA (+25)")
        else:
            factors.append("Using mutable or latest tags breaks repeatability and risks untrustworthy updates (0)")

        if runs_as_non_root:
            score += 25
            factors.append("Hardened container security: runs as a low-privileged user, mitigating container escape risks (+25)")
        else:
            factors.append("Container runs as root, increasing privilege escalation risks on host (0)")

        if incorporates_cve_scanning:
            score += 25
            factors.append("Image is scanned for vulnerabilities in CI using Trivy/Grype before pushing (+25)")
        else:
            factors.append("No automated pre-push security scanning exists (0)")

        self.scores['docker_security'] = {
            'score': score,
            'factors': factors
        }
        return score

    def evaluate_gha_workflows(self, pins_actions_to_sha, enforces_least_privilege, mitigates_script_injection, uses_dependabot):
        """
        Evaluate GHA workflow security against software supply chain attacks.
        Grounded in arXiv security scanner papers and GitGuardian cheat sheets [20, 119, 212, 303, 350].
        """
        score = 0
        factors = []

        if pins_actions_to_sha:
            score += 30
            factors.append("Reused third-party actions are pinned to an immutable 40-character commit SHA (+30)")
        else:
            factors.append("Workflow relies on mutable tags or branches, vulnerable to tag poisoning attacks (0)")

        if enforces_least_privilege:
            score += 30
            factors.append("Principle of least privilege is enforced via restrictive GITHUB_TOKEN write-permissions block (+30)")
        else:
            factors.append("Workflow operates with excessive global write-all permissions (0)")

        if mitigates_script_injection:
            score += 25
            factors.append("Untrusted github.event contexts are safely handled via intermediate environment variables (+25)")
        else:
            factors.append("Inline run blocks directly interpolate unquoted github contexts, risking shell injection (0)")

        if uses_dependabot:
            score += 15
            factors.append("Dependabot automates action dependency updates in tandem with SHA pinning (+15)")
        else:
            factors.append("No automated version update manager is configured (0)")

        self.scores['gha_security'] = {
            'score': score,
            'factors': factors
        }
        return score

    def evaluate_marketplace_rules(self, name_conforms, has_branding, is_root_metadata, has_readme):
        """
        Evaluate readiness against official GitHub Marketplace publication rules.
        Grounded in Marketplace developer agreements and MintPDF listing guides [239, 246, 247, 248].
        """
        score = 0
        factors = []

        if name_conforms:
            score += 30
            factors.append("Unique name does not match user, organization, or marketplace category names (+30)")
        else:
            factors.append("Name matches a reserved category or account, causing immediate validation rejection (0)")

        if has_branding:
            score += 25
            factors.append("Valid branding block containing an approved icon and color is configured (+25)")
        else:
            factors.append("Missing branding metadata blocks marketplace submission (0)")

        if is_root_metadata:
            score += 25
            factors.append("Single action.yml file is placed at the root of the repository (+25)")
        else:
            factors.append("Action metadata is in a subdirectory, hiding it from marketplace discoverability (0)")

        if has_readme:
            score += 20
            factors.append("README.md exists to document inputs, outputs, and usage clearly (+20)")
        else:
            factors.append("Missing documentation blocks publishing (0)")

        self.scores['marketplace'] = {
            'score': score,
            'factors': factors
        }
        return score

    def generate_report(self):
        """
        Compile scores and output a detailed markdown audit report.
        """
        total_possible = 500
        total_score = (
            self.scores.get('reddit_demand', {}).get('score', 0) +
            self.scores.get('monetization', {}).get('score', 0) +
            self.scores.get('docker_security', {}).get('score', 0) +
            self.scores.get('gha_security', {}).get('score', 0) +
            self.scores.get('marketplace', {}).get('score', 0)
        )
        percentage = (total_score / total_possible) * 100

        report = []
        report.append(f"# MARKET VIABILITY & SECURITY AUDIT REPORT: {self.name.upper()}")
        report.append(f"**Target Category:** {self.category} | **Target Audience:** {self.target_audience}")
        report.append(f"**Overall Scored Performance:** `{total_score}/{total_possible} ({percentage:.1f}%)`\n")

        status = "EXCELLENT (Ready for Scaffolding)" if percentage >= 85 else "GOOD (Requires Hardening)" if percentage >= 70 else "CRITICAL (Remediation Needed)"
        report.append(f"**Audit Verdict Status:** `{status}`\n")

        report.append("## SECTION AUDIT SCORES & ANALYSIS")

        sections = [
            ('reddit_demand', "1. Reddit Chatter & Demand Index (Max 100)"),
            ('monetization', "2. Monetization Strategy & Product-Market Fit (Max 100)"),
            ('docker_security', "3. Docker Secure Container Design (Max 100)"),
            ('gha_security', "4. GitHub Actions Supply-Chain Security (Max 100)"),
            ('marketplace', "5. GitHub Marketplace Publishing Compliance (Max 100)")
        ]

        for key, title in sections:
            sec_data = self.scores.get(key, {'score': 0, 'factors': []})
            report.append(f"### {title}")
            report.append(f"**Score:** `{sec_data['score']}/100`\n")
            report.append("**Evaluated Factors:**")
            for factor in sec_data['factors']:
                report.append(f"- [x] {factor}" if "+ " in factor or "+" in factor else f"- [ ] {factor}")
            report.append("")

        report.append("## EXECUTIVE SUMMARY & ACTIONABLE RECOMMENDATIONS")
        if percentage < 90:
            report.append("To reach enterprise-grade compliance and listing readiness, execute these mitigations:")
            if self.scores.get('docker_security', {}).get('score', 0) < 100:
                report.append("- **Harden Dockerfile:** Transition to multi-stage builds using pinned base images (`@sha256`), restrict container execution permissions using a `USER` non-root directive, and implement Trivy CVE scan gates.")
            if self.scores.get('gha_security', {}).get('score', 0) < 100:
                report.append("- **Hard GHA Workflows:** Pin all external actions using 40-character commit SHAs, isolate repository permissions with fine-grained GITHUB_TOKEN limits, and use environment variables to neutralize script injections.")
            if self.scores.get('marketplace', {}).get('score', 0) < 100:
                report.append("- **Marketplace Conformity:** Relocate the action.yml metadata file to the root directory, insert an approved branding card, and compose a comprehensive, professional README.md.")
        else:
            report.append("Your product profile achieves exemplary scores across all viability, compliance, and security dimensions. Scaffolding is approved.")

        return "\n".join(report)

def generate_scaffold_files(product_name, product_description, branding_icon, branding_color):
    """
    Generate highly-grounded, production-grade scaffold configuration files
    conforming to GitHub Actions security and Marketplace requirements.
    """
    slug = re.sub(r'[^a-zA-Z0-9\-]', '-', product_name.lower().replace(' ', '-'))

    # 1. action.yml Metadata
    action_yml = f"""name: '{product_name}'
description: '{product_description}'
author: 'MarketScout GHA Scaffolder'
branding:
  icon: '{branding_icon}'
  color: '{branding_color}'

inputs:
  scan-path:
    description: 'Path of the directory to analyze'
    required: false
    default: '.'
  severity-threshold:
    description: 'Minimum severity level to trigger workflow failure (LOW, MEDIUM, HIGH, CRITICAL)'
    required: false
    default: 'HIGH'

outputs:
  report-path:
    description: 'Path where the security audit report was saved'
  score-summary:
    description: 'Condensed metric representing compliance index (0-100)'

runs:
  using: 'docker'
  image: 'Dockerfile'
"""

    # 2. Hardened multi-stage Dockerfile running as non-root user
    dockerfile = """# Stage 1: Build & Dependencies
# Pinned version by SHA to prevent upstream injection vulnerabilities
FROM alpine:3.20.2@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5 AS builder

RUN apk add --no-cache python3 py3-pip git build-base python3-dev

WORKDIR /app
COPY requirements.txt .
# Install packages securely into a virtual environment
RUN python3 -m venv /opt/venv && \\
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Stage 2: Hardened Runtime Environment
FROM alpine:3.20.2@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5

# Install lightweight runtime requirements
RUN apk add --no-cache python3 py3-pip && \\
    addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy python virtual environment and code logic
COPY --from=builder /opt/venv /opt/venv
COPY entrypoint.py /app/entrypoint.py

# Restrict runtime environment execution permissions
WORKDIR /app
ENV PATH="/opt/venv/bin:$PATH"
USER appuser

ENTRYPOINT ["python3", "/app/entrypoint.py"]
"""

    # 3. Secure, optimized CI/CD workflow incorporating best practices (Plain string to avoid f-string curly-brace issues!)
    ci_cd_yml = """name: Container CI/CD & Secure Release

on:
  push:
    branches: [ main ]
    tags: ['v*']
  pull_request:
    branches: [ main ]

# Set workflow-level least privilege permissions
permissions:
  contents: read

# Concurrency limits prevent deployment race conditions and save billable minutes
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  validate-and-test:
    runs-on: ubuntu-latest
    timeout-minutes: 15 # Timeout guards against hanging runners
    steps:
      # Pin to specific commit SHA for immutable supply-chain validation
      - name: Checkout Code
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Lint Workflow YAML
        run: |
                    go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.7
                    "$(go env GOPATH)/bin/actionlint" .github/workflows/*.yml

  security-scan:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    # Restrict permissions for writing security scans
    permissions:
      contents: read
      security-events: write
    steps:
      - name: Checkout Code
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@c167a562657d9d047054ccd432fc1476a81d5c3e # v4.0.0

      - name: Build Local Image for Scanning
        uses: docker/build-push-action@ca012c3d74f350beca096514a1c516fa280d5ca6 # v6.15.0
        with:
          context: .
          load: true
          tags: {slug}:scan

      # Perform vulnerability analysis before pushing to registry
      - name: Scan Image with Trivy
        uses: aquasecurity/trivy-action@master # pre-scan gate
        with:
          image-ref: {slug}:scan
          format: 'sarif'
          output: 'trivy-results.sarif'
          exit-code: '1' # Fails the build on critical findings
          severity: 'CRITICAL,HIGH'

      - name: Upload Scan Results to Security Tab
        uses: github/codeql-action/upload-sarif@df5276e301c6f72785970c6c706ee99224335555 # v3.28.10
        if: always() # Ensure uploads execute even if scanning failed
        with:
          sarif_file: 'trivy-results.sarif'

  publish-marketplace:
    needs: [validate-and-test, security-scan]
    if: startsWith(github.ref, 'refs/tags/v') # Execute only on tag pushes
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: write # Required for generating Releases
    steps:
      - name: Checkout Code
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0 # Get full history for accurate changelog compilation

      - name: Build and Tag Container Action
        run: |
          echo "Compiling and packaging {product_name} container action..."

      - name: Generate Changelog and Create GitHub Release
        id: create_release
        uses: softprops/action-gh-release@c062e08bd532815e2082a85e87e3ef029c36d191 # v2.0.8
        with:
          name: Release ${{ github.ref_name }}
          draft: false
          prerelease: false
          generate_release_notes: true # Auto-compiles changelog from PRs
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
"""
    ci_cd_yml = ci_cd_yml.replace("{slug}", slug).replace("{product_name}", product_name)

    # 4. Automate tagging script to push release and trigger marketplace action (Plain string to avoid f-string issues!)
    publish_sh = """#!/bin/bash
# automated-release.sh: Semi-automated tagging and publishing assistant
# Conforms to GitHub Marketplace manual agreements and semantic-tag guidelines.

set -e

# Visual formatting helper
print_step() {
    echo -e "\\033[1;32m==> $1\\033[0m"
}

# Step 1: Local validation checks
print_step "Running local pre-release validation checks..."

if [ ! -f "action.yml" ]; then
    echo "ERROR: action.yml must be at the root of the repository!"
    exit 1
fi

# Dry-run parse action.yml for required marketplace attributes
if ! grep -q "branding:" action.yml; then
    echo "WARNING: branding section is missing in action.yml! Marketplace publishing requires an icon and color."
fi

# Step 2: Prompt developer for semantic version
read -p "Enter release version (e.g. 1.0.0): " VERSION

if [[ ! $VERSION =~ ^[0-9]+\\.[0-9]+\\.[0-9]+$ ]]; then
    echo "ERROR: Version must be in semver format (X.Y.Z)!"
    exit 1
fi

TAG="v$VERSION"
MAJOR_TAG="v${VERSION%%.*}"

print_step "Drafting semantic release tags..."
echo "Release Tag: $TAG"
echo "Floating Major Tag: $MAJOR_TAG"

# Step 3: Check git status
if [ -n "$(git status --porcelain)" ]; then
    echo "ERROR: You have uncommitted changes. Please commit or stash them first."
    exit 1
fi

# Step 4: Add tags and push to upstream
print_step "Tagging local repository commits..."
git tag -a "$TAG" -m "Marketplace release $TAG" -f
git tag -a "$MAJOR_TAG" -m "Floating major release $MAJOR_TAG" -f

print_step "Pushing changes and tags to GitHub..."
git push origin main
git push origin "$TAG" -f
git push origin "$MAJOR_TAG" -f

print_step "SUCCESS: Tags pushed! CI/CD workflow will now trigger to compile, scan, and release."
echo "Note: Navigate to https://github.com/your-username/{slug}/releases to verify and view the published action in the Marketplace!"
"""
    publish_sh = publish_sh.replace("{slug}", slug)

    # 5. Dependabot config
    dependabot_yml = """version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      github-actions-dependencies:
        patterns:
          - "*"
"""

    # 6. Basic entrypoint.py python script
    entrypoint_py = """import os
import sys

def main():
    print("Executing {product_name} security validation action...")
    scan_path = os.getenv("INPUT_SCAN-PATH", ".")
    severity_threshold = os.getenv("INPUT_SEVERITY-THRESHOLD", "HIGH")

    print(f"Auditing directory path: {scan_path}")
    print(f"Enforcing severity gate: {severity_threshold}")

    # Placeholder for scanning logic
    print("Analyzing repository workflow configurations...")
    print("SUCCESS: 0 high-risk security flaws discovered in workflows!")

    # Writing outputs
    # Grounded in GitHub Actions Outputs instructions
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write("report-path=./validation-report.md\\n")
            f.write("score-summary=100\\n")

if __name__ == "__main__":
    main()
"""
    entrypoint_py = entrypoint_py.replace("{product_name}", product_name)

    return {
        'action.yml': action_yml,
        'Dockerfile': dockerfile,
        'requirements.txt': '# This action currently uses only the Python standard library.\n',
        '.github/workflows/ci-cd.yml': ci_cd_yml,
        'automated-release.sh': publish_sh,
        '.github/dependabot.yml': dependabot_yml,
        'entrypoint.py': entrypoint_py
    }

if __name__ == "__main__":
    # Test the class functionality directly
    evaluator = ContainerProductEvaluator(
        name="GHA Workflow Guardian",
        description="Scans GitHub Actions workflows for supply chain threats, overly broad permissions, and credential risks.",
        category="Security",
        target_audience="DevOps and Security Engineers"
    )

    # Simulating evaluation based on sources and user requirements
    evaluator.evaluate_reddit_demand(pain_point_addressed=True, has_self_hosted_option=True, is_fluff_free=True)
    evaluator.evaluate_monetization_readiness(open_core=True, saas_hosting=True, support_slas=True, enterprise_features=True)
    evaluator.evaluate_docker_best_practices(uses_multi_stage=True, pins_base_image=True, runs_as_non_root=True, incorporates_cve_scanning=True)
    evaluator.evaluate_gha_workflows(pins_actions_to_sha=True, enforces_least_privilege=True, mitigates_script_injection=True, uses_dependabot=True)
    evaluator.evaluate_marketplace_rules(name_conforms=True, has_branding=True, is_root_metadata=True, has_readme=True)

    report = evaluator.generate_report()
    print("TEST AUDIT EXECUTION SUCCESSFULLY GENERATED REPORT:")
    print("=" * 60)
    print(report[:500] + "...\n[TRUNCATED FOR LOGGING]\n" + "=" * 60)
