#!/usr/bin/env bash
#
# validate-badssl.sh - regressione manuale di tlsanalyzer contro badssl.com
#
# Dependency-free: nessun jq, nessun tool esterno oltre a bash e coreutils.
# Da eseguire come smoke test prima di una release, NON in CI normale.
# badssl.com gira su infrastruttura donata: non metterlo in un loop.
#
# Uso:
#   ./validate-badssl.sh                      # esegue tutti i casi con gate
#   ./validate-badssl.sh --all                # include i casi osservativi
#   ./validate-badssl.sh --only expired,ecc256
#   TLSA_BIN=/path/to/tlsanalyzer ./validate-badssl.sh
#
# Se TLSA_BIN non e impostato lo script compila il binario da solo.
# NON usare "go run .": go run rimpiazza l exit code del programma con 1,
# rendendo indistinguibili policy fallita (3) ed errore runtime (1).
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CASES_FILE="${CASES_FILE:-$SCRIPT_DIR/badssl-cases.tsv}"
TLSA_BIN="${TLSA_BIN:-}"
TIMEOUT_SECS="${TIMEOUT_SECS:-30}"
SLEEP_BETWEEN="${SLEEP_BETWEEN:-1}"

KEEP_LOGS=0
RUN_ALL=0
ONLY=""

while [ $# -gt 0 ]; do
    case "$1" in
        --all)  RUN_ALL=1 ;;
        --keep-logs) KEEP_LOGS=1 ;;
        --only) shift; ONLY="${1:-}" ;;
        -h|--help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *)
            echo "Argomento non riconosciuto: $1" >&2
            exit 2
            ;;
    esac
    shift
done

# timeout non esiste nel sistema base di macOS: usa gtimeout se presente,
# altrimenti lancia senza limite di tempo.
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
else
    TIMEOUT_CMD=""
    echo "Nota: timeout/gtimeout non disponibili, i casi lenti non verranno interrotti." >&2
fi

BUILD_DIR=""
if [ -z "$TLSA_BIN" ]; then
    BUILD_DIR="$(mktemp -d)"
    TLSA_BIN="$BUILD_DIR/tlsanalyzer"
    echo "Compilo il binario in $TLSA_BIN ..." >&2
    if ! (cd "$SCRIPT_DIR/.." && go build -o "$TLSA_BIN" .); then
        echo "Build fallita." >&2
        rm -rf "$BUILD_DIR"
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Porta: forma verificata sul campo, i casi tls-v1-*:101x hanno dato esito atteso.
# Confermato che la CLI accetta --host H --port P.
# ---
# ---------------------------------------------------------------------------
target_args() {
    local host="$1" port="$2"
    if [ "$port" = "443" ]; then
        printf -- '--host %s' "$host"
    else
        printf -- '--host %s --port %s' "$host" "$port"
    fi
}

if [ "$KEEP_LOGS" -eq 1 ]; then
    OUTDIR="${OUTDIR:-$SCRIPT_DIR/badssl-logs}"
    mkdir -p "$OUTDIR"
else
    OUTDIR="$(mktemp -d)"
fi

cleanup() {
    [ "$KEEP_LOGS" -eq 1 ] || rm -rf "$OUTDIR"
    [ -n "$BUILD_DIR" ] && rm -rf "$BUILD_DIR"
    return 0
}
trap cleanup EXIT

pass=0
fail=0
observed=0
skipped=0
failed_ids=""

printf '%-18s %-34s %-6s %-6s %s\n' "CASE" "TARGET" "ATTESO" "OTTEN." "ESITO"
printf '%s\n' "--------------------------------------------------------------------------------------"

while IFS='|' read -r id host port extra_args expected_exit gate note; do
    case "$id" in ''|\#*) continue ;; esac

    if [ -n "$ONLY" ] && [[ ",$ONLY," != *",$id,"* ]]; then
        continue
    fi

    if [ "$gate" != "yes" ] && [ "$RUN_ALL" -eq 0 ] && [ -z "$ONLY" ]; then
        skipped=$((skipped + 1))
        continue
    fi

    target="$(target_args "$host" "$port")"
    logfile="$OUTDIR/$id.log"

    # shellcheck disable=SC2086
    if [ -n "$TIMEOUT_CMD" ]; then
        $TIMEOUT_CMD "$TIMEOUT_SECS" $TLSA_BIN $target $extra_args --no-clear >"$logfile" 2>&1
    else
        $TLSA_BIN $target $extra_args --no-clear >"$logfile" 2>&1
    fi
    actual_exit=$?

    if [ "$actual_exit" -eq 124 ]; then
        verdict="TIMEOUT"
    elif [ "$actual_exit" -eq "$expected_exit" ]; then
        verdict="PASS"
    else
        verdict="MISMATCH"
    fi

    if [ "$gate" = "yes" ]; then
        if [ "$verdict" = "PASS" ]; then
            pass=$((pass + 1))
        else
            fail=$((fail + 1))
            failed_ids="$failed_ids $id"
        fi
    else
        observed=$((observed + 1))
        [ "$verdict" = "PASS" ] || verdict="$verdict (osservativo)"
    fi

    printf '%-18s %-34s %-6s %-6s %s\n' \
        "$id" "$host:$port" "$expected_exit" "$actual_exit" "$verdict"

    sleep "$SLEEP_BETWEEN"
done < "$CASES_FILE"

printf '%s\n' "--------------------------------------------------------------------------------------"
printf 'gate: %d pass, %d fail | osservativi: %d | non eseguiti: %d\n' \
    "$pass" "$fail" "$observed" "$skipped"

if [ "$fail" -gt 0 ]; then
    printf 'Casi falliti:%s\n' "$failed_ids"
    if [ "$KEEP_LOGS" -eq 1 ]; then
        printf 'Log completi in %s\n' "$OUTDIR"
    else
        printf 'Rilancia con --keep-logs per conservare i log dei casi falliti.\n'
    fi
    exit 1
fi

exit 0
