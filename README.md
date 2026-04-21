# MCP OAuth Gateway

Ein zentraler OAuth-geschuetzter Reverse-Proxy fuer mehrere HTTP-basierte MCP-Server hinter einer gemeinsamen Domain.

## Architektur

Ein typisches Zielbild ist:

- Ein Reverse-Proxy leitet `https://mcp.example.com` komplett an den Gateway-Container weiter.
- Der Gateway fungiert gleichzeitig als OAuth Authorization Server und als geschuetzter Resource Server fuer mehrere MCP-Endpunkte.
- Jeder MCP-Server laeuft intern weiterhin als eigener Container und wird per Pfad angesprochen.

Beispiel:

- `https://mcp.example.com/n8n/mcp` -> Gateway -> `http://n8n-mcp:8080/mcp`
- `https://mcp.example.com/portainer/mcp` -> Gateway -> `http://portainer-mcp:8080/mcp`

Wichtig:

- Die oeffentliche MCP-URL ist `https://mcp.example.com/<route>/mcp`
- Nicht nur `https://mcp.example.com/<route>`
- Die zugehoerige Protected-Resource-Metadata liegt unter:
- `https://mcp.example.com/.well-known/oauth-protected-resource/<route>/mcp`

## Features

- Ein OAuth-Server fuer mehrere MCP-Server
- Dynamische Client-Registrierung
- Authorization Code Flow mit PKCE
- Resource-bound Bearer Tokens
- Account-Portal mit lokalem Benutzer-Store
- Admin-Dashboard unter `/admin`
- Routen im laufenden Betrieb erstellen, bearbeiten und loeschen
- Benutzer im Dashboard anlegen, Passwoerter zuruecksetzen, Admin-Rollen verwalten
- Deployment-Metadaten wie `MCP_HTTP_SESSION_MODE` oder interne Upstream-Env-Werte pro Route speichern
- Verschluesselter Auth-Store auf Volume
- Reverse-Proxy mit Header-Injektion pro Route
- Bootstrap-Admin ohne offenen Self-Signup

## Wichtige Umgebungsvariablen

- `MCP_GATEWAY_PUBLIC_BASE_URL`
- `MCP_GATEWAY_AUTH_MASTER_KEY`
- `MCP_GATEWAY_ROUTES_PATH`
- `MCP_GATEWAY_ALLOW_SELF_SIGNUP`
- `MCP_GATEWAY_BOOTSTRAP_EMAIL`
- `MCP_GATEWAY_BOOTSTRAP_PASSWORD`
- `MCP_GATEWAY_ALLOWED_EMAILS`
- `MCP_GATEWAY_ALLOWED_EMAIL_DOMAINS`

Der Master-Key muss genau 32 Bytes nach Base64-, Base64URL- oder Hex-Decoding ergeben.

## Deployment

1. Lege die Routen in `/config/routes.yaml` ab.
2. Starte den Container mit einem persistenten `/data`-Volume.
3. Leite in deinem Reverse-Proxy den kompletten Host `mcp.example.com` auf `http://<gateway-host>:8080`.
4. Die internen MCP-Container muessen im selben Docker-Netz wie der Gateway erreichbar sein.

Wenn `/config/routes.yaml` beim Start fehlt, erstellt der Gateway automatisch eine leere Datei mit `routes: []`. Das `/config`-Volume muss trotzdem les- und schreibbar sein, damit das Dashboard Routen speichern kann.

Ein Compose-Beispiel liegt in [docker-compose.example.yaml](/Volumes/ssd-data/Docker/mcp-oauth-gateway/docker-compose.example.yaml).

## Dashboard

Nach dem Login mit dem Bootstrap-Admin erreichst du das Dashboard unter:

- `https://mcp.example.com/admin`

Dort kannst du:

- neue MCP-Routen anlegen
- bestehende Routen bearbeiten oder loeschen
- `forward_headers` pflegen
- Deployment-Metadaten wie `MCP_HTTP_SESSION_MODE` oder interne `AUTH_TOKEN`-Werte fuer Upstreams dokumentieren
- Benutzer anlegen, loeschen und Admin-Rechte vergeben

Wichtig:

- Das Dashboard aendert die Gateway-Routen live und schreibt sie nach `routes.yaml` zurueck.
- Upstream-Umgebungsvariablen werden als Deployment-Metadaten gespeichert, aber nicht automatisch in Docker-Container injiziert.

## Beispielroute

Siehe [routes.example.yaml](/Volumes/ssd-data/Docker/mcp-oauth-gateway/routes.example.yaml).
