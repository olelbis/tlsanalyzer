# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26.3

FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

ARG VERSION=dev
ARG BUILD_TIME=unknown
ARG TARGETOS=linux
ARG TARGETARCH

RUN apk add --no-cache ca-certificates

COPY go.mod ./
COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-X 'github.com/olelbis/tlsanalyzer/build.Version=${VERSION}' -X 'github.com/olelbis/tlsanalyzer/build.BuildUser=Team tlsanalyzer' -X 'github.com/olelbis/tlsanalyzer/build.BuildTime=${BUILD_TIME}' -s -w" \
    -o /out/tlsanalyzer .

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/tlsanalyzer /tlsanalyzer

USER 65532:65532

ENTRYPOINT ["/tlsanalyzer"]
