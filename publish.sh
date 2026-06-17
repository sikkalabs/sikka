#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_FILE="$ROOT_DIR/release.json"
IMAGE_NAME="${IMAGE_NAME:-besoeasy/sikka}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64,linux/arm/v7}"
BUILDER_NAME="${BUILDER_NAME:-sikka-multiarch}"
DRY_RUN="${DRY_RUN:-false}"

require_command() {
  local command_name="$1"

  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "error: required command not found: $command_name" >&2
    exit 1
  fi
}

require_command docker
require_command sed

if [[ ! -f "$RELEASE_FILE" ]]; then
  echo "error: release file not found: $RELEASE_FILE" >&2
  exit 1
fi

if ! docker buildx version >/dev/null 2>&1; then
  echo "error: docker buildx is required" >&2
  exit 1
fi

VERSION="$(sed -n 's/.*"software_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$RELEASE_FILE" | head -n 1)"

if [[ -z "$VERSION" ]]; then
  echo "error: could not read software_version from $RELEASE_FILE" >&2
  exit 1
fi

read -rp "Publish stable release? (y/N): " publish_stable

if [[ "$publish_stable" =~ ^[Yy]$ ]]; then
  TAGS=(
    --tag "$IMAGE_NAME:latest"
    --tag "$IMAGE_NAME:$VERSION"
  )

  echo "Publishing STABLE"
  echo "Tags: latest, $VERSION"
else
  TAGS=(
    --tag "$IMAGE_NAME:test"
  )

  echo "Publishing TEST"
  echo "Tag: test"
fi

if ! docker buildx inspect "$BUILDER_NAME" >/dev/null 2>&1; then
  docker buildx create --name "$BUILDER_NAME" --driver docker-container --use >/dev/null
else
  docker buildx use "$BUILDER_NAME"
fi

docker buildx inspect --bootstrap >/dev/null

echo "Platforms: $PLATFORMS"

build_command=(
  docker buildx build
  --platform "$PLATFORMS"
  "${TAGS[@]}"
  --push
  "$ROOT_DIR"
)

if [[ "$DRY_RUN" == "true" ]]; then
  printf 'Dry run:'
  printf ' %q' "${build_command[@]}"
  printf '\n'
  exit 0
fi

"${build_command[@]}"