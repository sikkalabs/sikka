ARG GO_IMAGE=golang:1.23-alpine

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build-base

WORKDIR /src

# Download Go module dependencies
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source code
COPY metadata.go release.json ./
COPY cmd ./cmd
COPY internal ./internal

FROM build-base AS node-build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TARGETVARIANT=""

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eux; \
	export CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}"; \
	if [ "$GOARCH" = "arm" ] && [ -n "$TARGETVARIANT" ]; then export GOARM="${TARGETVARIANT#v}"; fi; \
	go build -trimpath -ldflags="-s -w" -o /out/sikka-node ./cmd/node

FROM alpine:3.23

# Install runtime dependencies (Tor, CA certificates, timezones) and setup user
RUN apk add --no-cache tor ca-certificates tzdata && \
	adduser -D -g '' -u 10001 sikka && \
	mkdir -p /home/sikka/data && \
	chown -R sikka:sikka /home/sikka

WORKDIR /home/sikka

COPY --from=node-build /out/sikka-node /usr/local/bin/sikka-node
COPY public2 ./public2

USER sikka

EXPOSE 64552

VOLUME ["/home/sikka/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:64552/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/sikka-node"]