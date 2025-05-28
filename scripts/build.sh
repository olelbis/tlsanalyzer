#!/bin/bash

GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)

echo "Compilo per $GOOS/$GOARCH..."

go build -v -ldflags="-X 'github.com/olelbis/sslscango/build.Version=$(cat VERSION)' -X 'github.com/olelbis/sslscango/build.BuildUser=Team sslscango' -X 'github.com/olelbis/sslscango/build.BuildTime=$(date)'"