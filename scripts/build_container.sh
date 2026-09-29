#!/usr/bin/env bash
# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

# Staged build packaging script for Agentic UEBA Cloud Run deployment.
# Implements Option A: Bakes canonical skills into container image at build time.
# Pulls from local ~/projects/ if present, or clones from GitHub if building in CI.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CANONICAL_SKILLS_ROOT="${SKILLS_ROOT:-${HOME}/projects}"
STAGING_DIR="${PROJECT_ROOT}/.build/skills"

echo "=== Staging Canonical Skills for Container Build (Option A) ==="
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}"

stage_skill() {
  local skill_name="$1"
  local git_url="$2"
  local local_path="${CANONICAL_SKILLS_ROOT}/${skill_name}"
  local target_path="${STAGING_DIR}/${skill_name}"

  if [ -d "${local_path}" ]; then
    echo "Staging from local disk: ${local_path} -> ${target_path}"
    rsync -av --delete \
      --exclude='.git' \
      --exclude='__pycache__' \
      --exclude='.pytest_cache' \
      "${local_path}/" "${target_path}/"
  else
    echo "Local path not found. Cloning from GitHub: ${git_url} -> ${target_path}"
    git clone --depth 1 "${git_url}" "${target_path}"
    rm -rf "${target_path}/.git"
  fi
}

stage_skill "secops-risk-metrics-multistage" "https://github.com/GooGKush/secops-risk-metrics-multistage.git"
stage_skill "secops-statistical-hunter" "https://github.com/GooGKush/secops-statistical-hunter.git"

echo "=== Staging Complete. Ready for Docker / Cloud Build ==="
ls -la "${STAGING_DIR}"
