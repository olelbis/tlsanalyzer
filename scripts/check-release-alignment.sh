#!/usr/bin/env bash
set -euo pipefail

latest_tag="$(git tag --sort=-version:refname | head -n 1)"
if [[ -z "${latest_tag}" ]]; then
  echo "No release tags found; skipping release alignment check."
  exit 0
fi

head_commit="$(git rev-parse HEAD)"
tag_commit="$(git rev-list -n 1 "${latest_tag}")"

if [[ "${head_commit}" != "${tag_commit}" ]]; then
  echo "main is ahead of latest release tag ${latest_tag}."
  echo "Create a release tag for HEAD so main and the latest release stay aligned."
  exit 1
fi

echo "main is aligned with latest release tag ${latest_tag}."
