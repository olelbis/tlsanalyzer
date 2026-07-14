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
  release_required=0
  while IFS= read -r file; do
    if [[ "${file}" != docs/* && "${file}" != "scripts/check-release-alignment.sh" ]]; then
      release_required=1
      break
    fi
  done < <(git diff --name-only "${latest_tag}"..HEAD)

  if [[ "${release_required}" -eq 0 ]]; then
    echo "main has only documentation or release-alignment check changes after latest release tag ${latest_tag}; release alignment is still acceptable."
    exit 0
  fi

  echo "main is ahead of latest release tag ${latest_tag}."
  echo "Create a release tag for HEAD so main and the latest release stay aligned."
  exit 1
fi

echo "main is aligned with latest release tag ${latest_tag}."
