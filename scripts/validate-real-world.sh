#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOST="${TLSANALYZER_VALIDATION_HOST:-www.example.com}"
SNI="${TLSANALYZER_VALIDATION_SNI:-example.com}"
EXPIRED_HOST="${TLSANALYZER_VALIDATION_EXPIRED_HOST:-expired.badssl.com}"
TIMEOUT="${TLSANALYZER_VALIDATION_TIMEOUT:-8}"
GO_CACHE="${GOCACHE:-${TMPDIR:-/tmp}/tlsanalyzer-go-build}"
EXPECTED_VERSION="${TLSANALYZER_EXPECTED_VERSION:-v$(cat "$REPO_ROOT/VERSION")}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tlsanalyzer-validation.XXXXXX")"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tlsanalyzer-build.XXXXXX")"
TLSA_BIN="$BUILD_DIR/tlsanalyzer"
trap 'rm -rf "$TMP_DIR" "$BUILD_DIR"' EXIT

# Il binario viene compilato una volta invece di usare "go run .".
# Motivo: go run rimpiazza l exit code del programma con 1, rendendo
# indistinguibili policy fallita (3), errore di parsing flag (2) ed
# errore runtime (1). Senza build non e possibile asserire sui codici.
echo "==> build"
(cd "$REPO_ROOT" && env GOCACHE="$GO_CACHE" go build -o "$TLSA_BIN" .)

LAST_EXIT=0

run_tlsanalyzer() {
  local status=0
  "$TLSA_BIN" "$@" || status=$?
  LAST_EXIT="$status"
  return 0
}

assert_exit() {
  local expected="$1"
  local context="$2"
  local file="${3:-}"
  if [ "$LAST_EXIT" -ne "$expected" ]; then
    echo "Exit code inatteso in: $context" >&2
    echo "Atteso: $expected, ottenuto: $LAST_EXIT" >&2
    if [ -n "$file" ] && [ -f "$file" ]; then
      echo "--- output ---" >&2
      cat "$file" >&2
    fi
    exit 1
  fi
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
assert_exit 0 "version" "$TMP_DIR/version.txt"
assert_contains "$TMP_DIR/version.txt" "tlsanalyzer"
assert_contains "$TMP_DIR/version.txt" "$EXPECTED_VERSION"

section "TLS 1.3 normal handshake"
run_tlsanalyzer --host "$HOST" --sni "$SNI" --min-version 1.3 --timeout "$TIMEOUT" --no-clear > "$TMP_DIR/tls13.txt"
assert_exit 0 "TLS 1.3 normal handshake" "$TMP_DIR/tls13.txt"
assert_contains "$TMP_DIR/tls13.txt" "TLS 1.3"
assert_contains "$TMP_DIR/tls13.txt" "Negotiated cipher suite (selected in this handshake):"
assert_contains "$TMP_DIR/tls13.txt" "Certificate validation: valid"
assert_not_contains "$TMP_DIR/tls13.txt" "Negotiated Cipher suite:"

section "TLS 1.3 raw probe"
run_tlsanalyzer --host "$HOST" --sni "$SNI" --min-version 1.3 --timeout "$TIMEOUT" --force-ciphers --no-clear > "$TMP_DIR/tls13-raw.txt"
assert_exit 0 "TLS 1.3 raw probe" "$TMP_DIR/tls13-raw.txt"
assert_contains "$TMP_DIR/tls13-raw.txt" "Raw-probed cipher suites (ClientHello-only support evidence):"
assert_contains "$TMP_DIR/tls13-raw.txt" "Raw probe:"
assert_contains "$TMP_DIR/tls13-raw.txt" "ClientHello-only ServerHello evidence"

section "JSON shape"
run_tlsanalyzer --host "$HOST" --sni "$SNI" --min-version 1.3 --timeout "$TIMEOUT" --force-ciphers --json > "$TMP_DIR/report.json"
assert_exit 0 "JSON shape" "$TMP_DIR/report.json"
assert_contains "$TMP_DIR/report.json" '"schema_version"'
assert_contains "$TMP_DIR/report.json" '"scanner_version"'
assert_contains "$TMP_DIR/report.json" '"cipher_discovery"'
assert_contains "$TMP_DIR/report.json" '"raw-probed"'
assert_contains "$TMP_DIR/report.json" '"cipher_probe_results"'

section "Markdown report"
run_tlsanalyzer --host "$HOST" --sni "$SNI" --min-version 1.3 --timeout "$TIMEOUT" --force-ciphers --markdown "$TMP_DIR/report.md" --no-clear > "$TMP_DIR/markdown.txt"
assert_exit 0 "Markdown report" "$TMP_DIR/markdown.txt"
assert_contains "$TMP_DIR/report.md" "# TLS Scan Report"
assert_contains "$TMP_DIR/report.md" "## Summary"
assert_contains "$TMP_DIR/report.md" "## TLS Versions"
assert_contains "$TMP_DIR/report.md" "## Cipher Suites"

section "policy pass smoke"
run_tlsanalyzer --host "$HOST" --sni "$SNI" --min-version 1.3 --timeout "$TIMEOUT" --policy modern --json > "$TMP_DIR/policy.json"
assert_exit 0 "policy pass smoke" "$TMP_DIR/policy.json"
assert_contains "$TMP_DIR/policy.json" '"policy"'
assert_contains "$TMP_DIR/policy.json" '"passed": true'

section "expired certificate smoke"
run_tlsanalyzer --host "$EXPIRED_HOST" --min-version 1.2 --timeout "$TIMEOUT" --json > "$TMP_DIR/expired.json"
assert_exit 0 "expired certificate smoke" "$TMP_DIR/expired.json"
assert_contains "$TMP_DIR/expired.json" '"certificate_validation_status": "invalid"'

section "exit code contract"
run_tlsanalyzer --host "$EXPIRED_HOST" --min-version 1.2 --timeout "$TIMEOUT" --policy modern --json > "$TMP_DIR/policy-fail.json"
assert_exit 3 "policy fallita deve uscire 3, non 1" "$TMP_DIR/policy-fail.json"
assert_contains "$TMP_DIR/policy-fail.json" '"passed": false'

run_tlsanalyzer --host "$HOST" --flag-inesistente > "$TMP_DIR/badflag.txt" 2>&1
assert_exit 2 "flag non valido deve uscire 2" "$TMP_DIR/badflag.txt"

echo
echo "Real-world validation passed."
echo "Host: $HOST"
echo "SNI: $SNI"
echo "Expired-cert host: $EXPIRED_HOST"
