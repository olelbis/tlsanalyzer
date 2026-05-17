#!/bin/sh

set -eu

VERSION="${1:-$(cat VERSION)}"
VERSION_NO_V="${VERSION#v}"
COMMIT="${GITHUB_SHA:-unknown}"
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
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-Package-tlsanalyzer"
    }
  ]
}
EOF
