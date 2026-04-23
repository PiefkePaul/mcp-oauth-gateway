ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

FROM --platform=$BUILDPLATFORM golang:1.24.2-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS
ARG TARGETARCH

RUN test -n "$TARGETOS" && test -n "$TARGETARCH" \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/mcp-oauth-gateway ./cmd/mcp-oauth-gateway

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /out/mcp-oauth-gateway /usr/local/bin/mcp-oauth-gateway

RUN mkdir -p /config /data

EXPOSE 8080

VOLUME ["/config", "/data"]

ENTRYPOINT ["/usr/local/bin/mcp-oauth-gateway"]
