#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOST="${TLSANALYZER_VALIDATION_HOST:-www.example.com}"
SNI="${TLSANALYZER_VALIDATION_SNI:-example.com}"
EXPIRED_HOST="${TLSANALYZER_VALIDATION_EXPIRED_HOST:-expired.badssl.com}"
TIMEOUT="${TLSANALYZER_VALIDATION_TIMEOUT:-8}"
GO_CACHE="${GOCACHE:-/private/tmp/tlsanalyzer-go-build}"
EXPECTED_VERSION="${TLSANALYZER_EXPECTED_VERSION:-v$(cat "$REPO_ROOT/VERSION")}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tlsanalyzer-validation.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

run_tlsanalyzer() {
  (cd "$REPO_ROOT" && env GOCACHE="$GO_CACHE" go run . "$@")
}

assert_contains() {
  local file="$1"
  local expected="$2"
  if ! grep -Fq "$expected" "$file"; then
    echo "Expected to find: $expected" >&2
    echo "In file: $file" >&2
    echo "--- output ---" >&2
    cat "$file" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file="$1"
  local unexpected="$2"
  if grep -Fq "$unexpected" "$file"; then
    echo "Did not expect to find: $unexpected" >&2
    echo "In file: $file" >&2
    echo "--- output ---" >&2
    cat "$file" >&2
    exit 1
  fi
}

section() {
  echo
  echo "==> $1"
}

section "version"
run_tlsanalyzer --version > "$TMP_DIR/version.txt"
assert_contains "$TMP_DIR/version.txt" "tlsanalyzer"
assert_contains "$TMP_DIR/version.txt" "$EXPECTED_VERSION"

section "TLS 1.3 normal handshake"
run_tlsanalyzer --host "$HOST" --sni "$SNI" --min-version 1.3 --timeout "$TIMEOUT" --no-clear > "$TMP_DIR/tls13.txt"
assert_contains "$TMP_DIR/tls13.txt" "TLS 1.3"
assert_contains "$TMP_DIR/tls13.txt" "Negotiated cipher suite (selected in this handshake):"
assert_contains "$TMP_DIR/tls13.txt" "Certificate validation: valid"
assert_not_contains "$TMP_DIR/tls13.txt" "Negotiated Cipher suite:"

section "TLS 1.3 raw probe"
run_tlsanalyzer --host "$HOST" --sni "$SNI" --min-version 1.3 --timeout "$TIMEOUT" --force-ciphers --no-clear > "$TMP_DIR/tls13-raw.txt"
assert_contains "$TMP_DIR/tls13-raw.txt" "Raw-probed cipher suites (ClientHello-only support evidence):"
assert_contains "$TMP_DIR/tls13-raw.txt" "Raw probe:"
assert_contains "$TMP_DIR/tls13-raw.txt" "ClientHello-only ServerHello evidence"

section "JSON shape"
run_tlsanalyzer --host "$HOST" --sni "$SNI" --min-version 1.3 --timeout "$TIMEOUT" --force-ciphers --json > "$TMP_DIR/report.json"
assert_contains "$TMP_DIR/report.json" '"schema_version"'
assert_contains "$TMP_DIR/report.json" '"scanner_version"'
assert_contains "$TMP_DIR/report.json" '"cipher_discovery"'
assert_contains "$TMP_DIR/report.json" '"raw-probed"'
assert_contains "$TMP_DIR/report.json" '"cipher_probe_results"'

section "Markdown report"
run_tlsanalyzer --host "$HOST" --sni "$SNI" --min-version 1.3 --timeout "$TIMEOUT" --force-ciphers --markdown "$TMP_DIR/report.md" --no-clear > "$TMP_DIR/markdown.txt"
assert_contains "$TMP_DIR/report.md" "# TLS Scan Report"
assert_contains "$TMP_DIR/report.md" "## Summary"
assert_contains "$TMP_DIR/report.md" "## TLS Versions"
assert_contains "$TMP_DIR/report.md" "## Cipher Suites"

section "policy pass smoke"
run_tlsanalyzer --host "$HOST" --sni "$SNI" --min-version 1.3 --timeout "$TIMEOUT" --policy modern --json > "$TMP_DIR/policy.json"
assert_contains "$TMP_DIR/policy.json" '"policy"'

section "expired certificate smoke"
run_tlsanalyzer --host "$EXPIRED_HOST" --min-version 1.2 --timeout "$TIMEOUT" --json > "$TMP_DIR/expired.json"
assert_contains "$TMP_DIR/expired.json" '"certificate_validation_status"'
assert_contains "$TMP_DIR/expired.json" '"invalid"'

echo
echo "Real-world validation passed."
echo "Host: $HOST"
echo "SNI: $SNI"
echo "Expired-cert host: $EXPIRED_HOST"
