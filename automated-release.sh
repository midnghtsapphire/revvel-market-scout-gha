#!/bin/bash
# automated-release.sh: Semi-automated tagging and publishing assistant
# Conforms to GitHub Marketplace manual agreements and semantic-tag guidelines.

set -e

# Visual formatting helper
print_step() {
    echo -e "\033[1;32m==> $1\033[0m"
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

if [[ ! $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
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
echo "Note: Navigate to https://github.com/midnghtsapphire/revvel-market-scout-gha/releases to verify and publish the action to GitHub Marketplace."
