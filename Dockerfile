ARG GO_IMAGE=golang:1.23-alpine

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build-base

WORKDIR /src

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY metadata.go ./
COPY release.json ./
COPY cmd ./cmd
COPY internal ./internal

FROM build-base AS node-build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TARGETVARIANT=""

RUN set -eux; \
	export CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}"; \
	if [ "$GOARCH" = "arm" ] && [ -n "$TARGETVARIANT" ]; then export GOARM="${TARGETVARIANT#v}"; fi; \
	go build -o /out/sikka-node ./cmd/node

FROM alpine:3.23

RUN apk add --no-cache tor && \
	adduser -D -g '' sikka && \
	mkdir -p /home/sikka/data && \
	chown -R sikka:sikka /home/sikka

WORKDIR /home/sikka

COPY --from=node-build /out/sikka-node /usr/local/bin/sikka-node
COPY public ./public

USER sikka

EXPOSE 64552

VOLUME ["/home/sikka/data"]

ENTRYPOINT ["/usr/local/bin/sikka-node"]