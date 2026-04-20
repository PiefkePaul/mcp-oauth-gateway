FROM golang:1.24.2-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/mcp-oauth-gateway ./cmd/mcp-oauth-gateway

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /nonexistent --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY --from=build /out/mcp-oauth-gateway /usr/local/bin/mcp-oauth-gateway

RUN mkdir -p /config /data \
    && chown -R appuser:appuser /config /data

USER appuser

EXPOSE 8080

VOLUME ["/config", "/data"]

ENTRYPOINT ["/usr/local/bin/mcp-oauth-gateway"]
