#!/bin/sh

set -eu

VERSION="${1:-$(cat VERSION)}"
VERSION_NO_V="${VERSION#v}"
COMMIT="${GITHUB_SHA:-unknown}"
GO_VERSION="NOASSERTION"
if command -v go >/dev/null 2>&1; then
  detected="$(go env GOVERSION 2>/dev/null || true)"
  if [ -n "$detected" ]; then
    GO_VERSION="${detected#go}"
  fi
fi
CREATED="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
NAMESPACE="https://github.com/olelbis/tlsanalyzer/sbom/${VERSION}/${COMMIT}"

cat <<EOF
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "tlsanalyzer-${VERSION}",
  "documentNamespace": "${NAMESPACE}",
  "creationInfo": {
    "created": "${CREATED}",
    "creators": [
      "Tool: tlsanalyzer release workflow",
      "Organization: Team tlsanalyzer"
    ]
  },
  "packages": [
    {
      "name": "tlsanalyzer",
      "SPDXID": "SPDXRef-Package-tlsanalyzer",
      "versionInfo": "${VERSION_NO_V}",
      "downloadLocation": "https://github.com/olelbis/tlsanalyzer/releases/tag/${VERSION}",
      "filesAnalyzed": false,
      "licenseConcluded": "MIT",
      "licenseDeclared": "MIT",
      "copyrightText": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:golang/github.com/olelbis/tlsanalyzer@${VERSION_NO_V}"
        }
      ]
    },
    {
      "name": "go",
      "SPDXID": "SPDXRef-Package-go-toolchain",
      "versionInfo": "${GO_VERSION}",
      "downloadLocation": "https://go.dev/dl/",
      "filesAnalyzed": false,
      "licenseConcluded": "BSD-3-Clause",
      "licenseDeclared": "BSD-3-Clause",
      "copyrightText": "NOASSERTION",
      "comment": "Go toolchain used to build tlsanalyzer; the standard library is linked into the binary.",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:golang/std@${GO_VERSION}"
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-Package-tlsanalyzer"
    },
    {
      "spdxElementId": "SPDXRef-Package-go-toolchain",
      "relationshipType": "BUILD_TOOL_OF",
      "relatedSpdxElement": "SPDXRef-Package-tlsanalyzer"
    }
  ]
}
EOF
