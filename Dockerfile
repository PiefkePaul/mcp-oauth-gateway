ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

FROM --platform=$BUILDPLATFORM golang:1.27-trixie AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS
ARG TARGETARCH

RUN test -n "$TARGETOS" && test -n "$TARGETARCH" \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/mcp-oauth-gateway ./cmd/mcp-oauth-gateway

FROM debian:trixie-slim

# Fixed, unprivileged account. The numeric IDs are part of the image contract:
# bind-mounted /config and /data must be writable for them (or the container is
# started with a different `user:` that owns those folders).
ARG APP_UID=10001
ARG APP_GID=10001

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid "$APP_GID" gateway \
    && useradd --system --uid "$APP_UID" --gid "$APP_GID" --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin gateway \
    && install -d -o "$APP_UID" -g "$APP_GID" -m 0750 /config /data

WORKDIR /app

COPY --from=build /out/mcp-oauth-gateway /usr/local/bin/mcp-oauth-gateway

# No home directory exists; point HOME and TMPDIR at /tmp so that the gateway
# and STDIO children also work with a read-only root filesystem (tmpfs on /tmp).
ENV HOME=/tmp \
    TMPDIR=/tmp

EXPOSE 8080

VOLUME ["/config", "/data"]

# Numeric so that `runAsNonRoot`-style checks can verify it without /etc/passwd.
USER ${APP_UID}:${APP_GID}

ENTRYPOINT ["/usr/local/bin/mcp-oauth-gateway"]
