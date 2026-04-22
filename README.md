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
- Zusaetzlich antwortet `https://mcp.example.com/.well-known/oauth-protected-resource` als Gateway-weite Fallback-Metadata fuer Clients wie Open WebUI, die Root-Discovery nutzen.
- Open WebUI muss den Gateway aus seinem eigenen Container erreichen koennen. Wenn Open WebUI in Docker laeuft, ist `localhost` meistens der Open-WebUI-Container selbst; nutze dann die NAS-IP, die oeffentliche HTTPS-Domain oder ein gemeinsames Docker-Netz.
- Fuer OAuth-Redirects sollte Open WebUI `WEBUI_URL` auf seine oeffentliche HTTPS-URL gesetzt haben. Falls du in einem privaten LAN bewusst eine HTTP-Redirect-URI nutzen musst, erlaube deren Origin explizit mit `MCP_GATEWAY_ALLOWED_REDIRECT_ORIGINS`, z.B. `http://openwebui.internal:8080`.

## Features

- Ein OAuth-Server fuer mehrere MCP-Server
- Dynamische Client-Registrierung
- RFC-7591 Dynamic Client Registration mit RFC-7592 Client Configuration Endpoint
- Authorization Code Flow mit PKCE
- OAuth-Clients ohne Secret sowie confidential clients mit `client_secret_post` oder `client_secret_basic`
- Resource-bound Bearer Tokens
- Account-Portal mit lokalem Benutzer-Store
- Oeffentliches MCP-Katalog-Dashboard unter `/` und Gateway-Dokumentation unter `/docs`
- Admin-Dashboard unter `/admin`
- Routen im laufenden Betrieb erstellen, bearbeiten und loeschen
- Benutzer, Gruppen, Gruppenmitgliedschaften und Admin-Rollen im Dashboard verwalten
- Eigene Account-Seite mit Passwortwechsel und Logout
- Pro Route Zugriffsregeln setzen: public, restricted oder admin-only
- Private Routen aus dem oeffentlichen Katalog ausblenden
- Routen-Konfiguration importieren und exportieren
- Deployment-Metadaten wie `MCP_HTTP_SESSION_MODE` oder interne Upstream-Env-Werte pro Route speichern
- Optionales Docker-Management fuer HTTP-MCP-Container aus bestehenden Images
- Native STDIO-MCP-Routen ohne zusaetzlichen Adapter-Container
- Optionaler, abgesicherter Artefakt-Build: Upload oder HTTPS/GitHub-Release-Download mit SHA-256-Pruefung und generiertem Dockerfile
- OpenAPI-3.x-Routen, die Operationen aus einer OpenAPI-Spec als MCP-Tools bereitstellen
- Verwaltete Docker-Deployments im Dashboard anlegen, starten, stoppen und entfernen
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
- `MCP_GATEWAY_ALLOWED_REDIRECT_ORIGINS`
- `MCP_GATEWAY_ACCESS_LOG`
- `MCP_GATEWAY_DOCKER_MANAGEMENT_ENABLED`
- `MCP_GATEWAY_DOCKER_HOST`
- `MCP_GATEWAY_DOCKER_NETWORKS`
- `MCP_GATEWAY_DOCKER_RESTART_POLICY`
- `MCP_GATEWAY_BUILD_ENABLED`
- `MCP_GATEWAY_BUILD_MAX_ARTIFACT_MB`
- `MCP_GATEWAY_BUILD_ALLOWED_DOWNLOAD_HOSTS`
- `MCP_GATEWAY_BUILD_ALLOW_ANY_DOWNLOAD_HOST`
- `MCP_GATEWAY_BUILD_DEFAULT_BASE_IMAGE`
- `MCP_GATEWAY_BUILD_ALLOWED_BASE_IMAGES`
- `MCP_GATEWAY_OPENAPI_STORE_DIR`

Der Master-Key muss genau 32 Bytes nach Base64-, Base64URL- oder Hex-Decoding ergeben.

## Deployment

1. Lege die Routen in `/config/routes.yaml` ab.
2. Starte den Container mit einem persistenten `/data`-Volume.
3. Leite in deinem Reverse-Proxy den kompletten Host `mcp.example.com` auf `http://<gateway-host>:8080`.
4. Die internen MCP-Container muessen im selben Docker-Netz wie der Gateway erreichbar sein.

Wenn `/config/routes.yaml` beim Start fehlt, erstellt der Gateway automatisch eine leere Datei mit `routes: []`. Das `/config`-Volume muss trotzdem les- und schreibbar sein, damit das Dashboard Routen speichern kann.

Ein Compose-Beispiel liegt in [docker-compose.example.yaml](/Volumes/ssd-data/Docker/mcp-oauth-gateway/docker-compose.example.yaml).

## Managed Deployments

Der Gateway kann HTTP-basierte MCP-Container direkt aus dem Admin-Dashboard erstellen. Diese Docker-Funktion ist standardmaessig deaktiviert, weil der Docker-Socket sehr maechtig ist.

Zum Aktivieren:

- `MCP_GATEWAY_DOCKER_MANAGEMENT_ENABLED=true`
- `MCP_GATEWAY_DOCKER_HOST=unix:///var/run/docker.sock`
- `/var/run/docker.sock:/var/run/docker.sock` als Volume mounten
- `MCP_GATEWAY_DOCKER_NETWORKS` auf ein Docker-Netz setzen, in dem Gateway und neue MCP-Container gemeinsam erreichbar sind

Wichtig:

- Docker-Socket-Zugriff entspricht praktisch Host-Docker-Adminrechten. Aktiviere das nur fuer vertrauenswuerdige Admins.
- Phase 2 verwaltet HTTP-/Streamable-HTTP-MCP-Container aus bestehenden Images.
- Beim Anlegen eines Deployments erstellt der Gateway den Container und speichert automatisch eine Route mit `deployment`-Metadaten in `routes.yaml`.

### Artefakt-Builds

Phase 4 kann aus einem verifizierten Binary-Artefakt ein eigenes Docker-Image bauen. Der Gateway nimmt dabei bewusst keine freien Dockerfiles und keine frei eingegebenen Shell-Kommandos entgegen.

Aktivierung:

- `MCP_GATEWAY_DOCKER_MANAGEMENT_ENABLED=true`
- `MCP_GATEWAY_BUILD_ENABLED=true`
- `/var/run/docker.sock:/var/run/docker.sock` als Volume mounten
- `MCP_GATEWAY_BUILD_ALLOWED_BASE_IMAGES` auf die erlaubten Base Images begrenzen

Sicherheitsregeln:

- Uploads und Downloads brauchen immer eine SHA-256-Checksum.
- Downloads muessen HTTPS nutzen und sind standardmaessig auf GitHub-Release-Hosts beschraenkt.
- Wenn `MCP_GATEWAY_BUILD_ALLOW_ANY_DOWNLOAD_HOST=true` gesetzt wird, blockiert der Gateway weiterhin private, Loopback-, Link-Local- und unspezifizierte Zieladressen.
- Entpackt werden nur `tar.gz` und `zip`; absolute Pfade, Traversal, Symlinks, Hardlinks und Spezialdateien werden abgelehnt.
- Das Dockerfile wird vom Gateway generiert und kopiert nur das verifizierte Artefakt nach `/usr/local/bin/mcp-entrypoint`.
- Optionale Start-Argumente werden als JSON-`ENTRYPOINT` geschrieben. Sie werden nicht durch eine Shell interpretiert.

### Native STDIO Routes

Phase 3 erlaubt native STDIO-MCPs direkt im Gateway-Prozess. Dafuer wird kein `supergateway`, kein `mcpo` und kein weiterer Adapter-Container benoetigt.

Eine STDIO-Route sieht so aus:

```yaml
routes:
  - id: local-portainer
    display_name: Local Portainer STDIO
    transport: stdio
    path_prefix: /local-portainer
    scopes_supported:
      - mcp
    access:
      visibility: private
      mode: admin
    stdio:
      command: /tools/portainer-mcp
      args:
        - -server
        - https://portainer:9443
        - -token
        - REPLACE_WITH_PORTAINER_TOKEN
        - -tools
        - /data/portainer-tools.yaml
      env:
        EXAMPLE_ENV: example
```

Wichtig:

- Der Command-Pfad muss im Gateway-Container existieren. Host-Binaries muessen daher als Volume gemountet werden, z.B. `./tools:/tools:ro`.
- Jeder Client bekommt eine eigene `Mcp-Session-Id`; der Gateway startet dafuer einen eigenen STDIO-Prozess und beendet ihn bei `DELETE` oder beim Routenwechsel.
- Der Gateway bridged JSON-RPC direkt zwischen Streamable HTTP und STDIO. Server-seitige Reverse-Requests wie Sampling werden aktuell bewusst abgelehnt.
- Admins sollten nur vertrauenswuerdige Executables eintragen. Native STDIO-Kommandos laufen mit den Rechten des Gateway-Containers.

### OpenAPI Routes

Phase 5 kann OpenAPI-3.x-Spezifikationen als MCP-Tools bereitstellen. Jede Operation unter `paths` wird zu einem Tool; `operationId` wird als Tool-Name genutzt, ansonsten erzeugt der Gateway einen stabilen Namen aus HTTP-Methode und Pfad.

Beispiel:

```yaml
routes:
  - id: example-openapi
    display_name: Example OpenAPI Tools
    transport: openapi
    path_prefix: /example-openapi
    scopes_supported:
      - mcp
    openapi:
      spec_path: /data/openapi/example.yaml
      base_url: https://api.example.com
      headers:
        Authorization: "Bearer REPLACE_WITH_INTERNAL_API_TOKEN"
      timeout_seconds: 30
```

Hinweise:

- Unterstuetzt werden OpenAPI-3.x-Dokumente, aktuell getestet gegen die offizielle OpenAPI Specification 3.2.0.
- Der Gateway verarbeitet `path`, `query`, `querystring`, `header` und `cookie` Parameter. OpenAPI-Header-Parameter fuer `Accept`, `Content-Type` und `Authorization` werden gemaess OAS nicht als frei modellierte Parameter uebernommen; interne API-Auth setzt du ueber `openapi.headers`.
- Request Bodies mit `application/json`, JSON-Suffix-Medientypen, `text/plain` und `application/x-www-form-urlencoded` werden unterstuetzt.
- Lokale `$ref`s werden begrenzt aufgeloest; externe `$ref`s werden aus Sicherheitsgruenden nicht automatisch nachgeladen.
- OpenAPI-Routen nutzen weiterhin den Gateway-OAuth-Schutz. Das bedeutet: Clients sehen nur den MCP-Endpunkt des Gateways, nicht direkt deine Ziel-API.
- Offizielle Referenz: [OpenAPI Specification](https://spec.openapis.org/oas/latest.html).

## Dashboard

Nach dem Login mit dem Bootstrap-Admin erreichst du das Dashboard unter:

- `https://mcp.example.com/admin`

Dort kannst du:

- neue MCP-Routen anlegen
- bestehende Routen bearbeiten oder loeschen
- `forward_headers` pflegen
- Route-IDs leer lassen, damit sie automatisch aus Display Name oder Path Prefix erzeugt werden
- im Deployments-Reiter HTTP-MCP-Container aus Docker-Images oder native STDIO-Routen erstellen
- im Deployments-Reiter aus verifizierten Artefakten eigene Images bauen
- OpenAPI-Specs hochladen oder per URL referenzieren und als MCP-Route speichern
- Routen als public oder private markieren
- Routen auf alle angemeldeten Nutzer, bestimmte Nutzer/Gruppen oder nur Admins beschraenken
- Gruppen anlegen und Nutzern zuweisen
- Deployment-Metadaten wie `MCP_HTTP_SESSION_MODE` oder interne `AUTH_TOKEN`-Werte fuer Upstreams dokumentieren
- Benutzer anlegen, loeschen und Admin-Rechte vergeben
- `routes.yaml` importieren und exportieren

Wichtig:

- Das Dashboard aendert die Gateway-Routen live und schreibt sie nach `routes.yaml` zurueck.
- Upstream-Umgebungsvariablen werden bei HTTP-Routen als Deployment-Metadaten gespeichert. Bei STDIO-Routen werden `stdio.env`-Werte an den gestarteten Prozess uebergeben.
- Full Export kann interne Tokens in `forward_headers`, `upstream_environment` oder `stdio.env` enthalten. Nutze Redacted Export, wenn du die Datei teilen willst.

## Open WebUI Hinweise

Open WebUI speichert nach `Register Client` die OAuth-Client-Informationen in seiner eigenen Tool-Server-Konfiguration. Wenn du die MCP-URL oder die Gateway-Domain aenderst, reicht es nicht immer, nur das URL-Feld anzupassen. Registriere den Client erneut und speichere die Verbindung danach erneut.

Wenn Open WebUI beim Start des OAuth-Flows auf eine alte Domain wie `https://old.example.com/authorize` umleitet, kommt diese URL in der Regel aus gespeicherten Open-WebUI-`oauth_client_info`, nicht aus dem Gateway. Loesche in Open WebUI die betreffende Tool-Server-Verbindung oder fuehre `Register Client` erneut aus und speichere die Verbindung.

Fuer lokale Tests muss `MCP_GATEWAY_PUBLIC_BASE_URL` exakt zu der URL passen, die Open WebUI nutzt, z.B. `http://gateway.internal:18080`. Die OAuth-Metadata und der `WWW-Authenticate` Header muessen dieselbe Basis-URL ausgeben.

## OAuth Standards

Der Gateway implementiert den OAuth Authorization Code Flow mit PKCE fuer HTTP-basierte MCP-Clients. Die dynamische Client-Registrierung ist offen, damit generische MCP-Clients sich ohne Vorab-Konfiguration registrieren koennen.

Unterstuetzt:

- RFC 6749 Authorization Code und Refresh Token Grants
- RFC 7591 `POST /register` fuer Dynamic Client Registration
- RFC 7592 `GET`, `PUT` und `DELETE /register/{client_id}` mit `registration_access_token`
- `token_endpoint_auth_method`: `none`, `client_secret_post`, `client_secret_basic`
- Kurzlebige, single-use Authorization Codes
- Refresh-Token-Rotation bei jedem Refresh
- Resource-bound Access Tokens fuer MCP-Routen

Bewusst nicht enthalten:

- GitHub OAuth als Login-Provider. Der Gateway nutzt aktuell lokale Nutzerkonten; externe Identity Provider sind fuer eine spaetere Phase vorgesehen.
- Token Introspection, JWT Access Tokens, DPoP, PAR oder mTLS.
- Vollstaendige OpenID-Connect-Identitaetsfunktionen. `/.well-known/openid-configuration` ist nur als Kompatibilitaetsalias fuer Clients vorhanden.

## Oeffentliches Dashboard und Docs

Der Gateway zeigt unter `https://mcp.example.com/` alle Routen, die nicht als private markiert sind. Jede sichtbare Route bekommt ausserdem eine Docs-Seite:

- Gateway-Katalog: `https://mcp.example.com/`
- Gateway-Dokumentation: `https://mcp.example.com/docs`
- Route-Dokumentation: `https://mcp.example.com/<route>/docs`
- Remote MCP URL fuer Clients: `https://mcp.example.com/<route>/mcp`

Private Routen erscheinen nicht im Katalog. Ihre Docs-Seite ist nur fuer angemeldete Nutzer mit passender Berechtigung sichtbar.

## Route Access

Jede Route kann eine optionale `access`-Sektion enthalten. Fehlt sie, gilt automatisch:

```yaml
access:
  visibility: public
  mode: public
```

Unterstuetzte Werte:

- `visibility: public` zeigt die Route im oeffentlichen Dashboard.
- `visibility: private` versteckt die Route aus dem Katalog.
- `mode: public` erlaubt allen angemeldeten Nutzern die Nutzung.
- `mode: restricted` erlaubt nur explizit ausgewaehlten Nutzern oder Gruppen die Nutzung.
- `mode: admin` erlaubt nur Admin-Nutzern die Nutzung.

## Beispielroute

Siehe [routes.example.yaml](/Volumes/ssd-data/Docker/mcp-oauth-gateway/routes.example.yaml).
