#!/bin/bash

set -e

APP_NAME="tlsanalyzer"
MODULE_PATH="github.com/olelbis/tlsanalyzer/build"
OUTPUT_DIR="build"
VERSION=$(cat VERSION 2>/dev/null || echo "dev")
BUILD_USER="Team tlsanalyzer"
BUILD_TIME=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

# Defaults
GOOS_CURR=$(go env GOOS)
GOARCH_CURR=$(go env GOARCH)
GOOS="$GOOS_CURR"
GOARCH="$GOARCH_CURR"
OUT="$APP_NAME"
ALL=false

# Parse arguments
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --os) GOOS="$2"; shift ;;
    --arch) GOARCH="$2"; shift ;;
    --out) OUT="$2"; shift ;;
    --all) ALL=true ;;
    *) echo "❌ Unknown option: $1"; exit 1 ;;
  esac
  shift
done

mkdir -p "$OUTPUT_DIR"

# Function to build a single target
build_target() {
  local GOOS="$1"
  local GOARCH="$2"
  local output_name="$APP_NAME-$GOOS-$GOARCH"
  [ "$GOOS" = "windows" ] && output_name+=".exe"

  echo "📦 Building for $GOOS/$GOARCH -> $output_name"

  env GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
  go build -v -ldflags="-X '$MODULE_PATH.Version=$VERSION' -X '$MODULE_PATH.BuildUser=$BUILD_USER' -X '$MODULE_PATH.BuildTime=$BUILD_TIME'" \
  -o "$OUTPUT_DIR/$output_name" .
}

if [ "$ALL" = true ]; then
  targets=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
  )
  for t in "${targets[@]}"; do
    IFS=/ read -r os arch <<< "$t"
    build_target "$os" "$arch"
  done
else
  build_target "$GOOS" "$GOARCH"
  mv "$OUTPUT_DIR/$APP_NAME-$GOOS-$GOARCH" "$OUTPUT_DIR/$OUT" 2>/dev/null || true
fi
