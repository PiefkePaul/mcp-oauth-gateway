# Upstream-Bearer aus einer Secrets-Datei (z. B. Infisical-Agent)

Seit PR #22 kann das Gateway die Upstream-Bearer seiner Routen aus einer Datei lesen, statt sie nur im verschlüsselten Auth-Store zu halten. Damit lassen sich alle Werte zentral in einem Secret-Manager wie Infisical pflegen. Ein Agent schreibt die Datei, das Gateway übernimmt Änderungen ohne Neustart.

Diese Seite beschreibt den Mechanismus und ein Betriebsmuster. Konkrete Installationsdaten (Pfade, Ordner, Routenliste) gehören nicht in dieses öffentliche Repo.

## Einstellungen und Format

Siehe `README.md`, Abschnitt zu `MCP_GATEWAY_ROUTE_SECRETS_*` (Datei, Neuladen, `STRICT`, `HINT`). Kurz:
- Die Datei wird alle `MCP_GATEWAY_ROUTE_SECRETS_RELOAD` (Standard 10 s) geprüft. Ein neuer Inhalt gilt nach höchstens zwei Intervallen, ohne Neustart; `SIGHUP` lädt sofort. Das Log nennt nur Schlüsselnamen: `secrets file loaded keys=N changed=A,B`.
- Zeilen `KEY='wert'` (Format des Infisical-Agents). Schlüssel = Route-ID in Großbuchstaben, jedes Zeichen außer `A-Z0-9` wird `_` (Route `german-legal-mcp` → `GERMAN_LEGAL_MCP`), sofern die Route kein eigenes `upstream_bearer_key` setzt.

## Reihenfolge beim Weiterleiten

1. Persönlicher Nutzer-Bearer aus dem Auth-Store
2. Wert aus der Secrets-Datei
3. Routen-Bearer aus dem Auth-Store (Rückfall, z. B. während einer Umstellung)
4. kein Bearer

Ein im Admin-Dashboard gespeicherter „Globaler Upstream Bearer“ greift also nur noch, wenn der Schlüssel in der Datei fehlt. Wer komplett umgestellt hat, kann ihn im Dashboard leeren und danach `MCP_GATEWAY_ROUTE_SECRETS_STRICT=true` setzen; dann wird nie mehr ein gespeicherter Bearer gesendet. Mit `MCP_GATEWAY_ROUTE_SECRETS_HINT` zeigt das Routen-Formular, wo der Wert gepflegt wird.

## Betriebsmuster mit Infisical

- Ein Ordner für das Gateway (z. B. `/gateway-routen`), in dem je Route ein Schlüssel `<ROUTE_ID_GROSS>` steht.
- Braucht der MCP-Server hinter der Route denselben Wert (eingehender Bearer), liegt der Wert im Ordner des MCP-Servers. Im Gateway-Ordner steht nur ein Infisical-Verweis `${<umgebung>.<ordner>.<KEY>}`. So gibt es jeden Wert genau einmal.
- Wird der Wert nur vom Gateway genutzt (z. B. ein Token, das an eine fremde API durchgereicht wird), steht er direkt im Gateway-Ordner.
- Der Infisical-Agent schreibt die Datei mit Rechten `600` und dem Besitzer des Gateway-Prozesses (Image-Standard uid `10001`). Die Datei wird nur lesend in den Container eingebunden.

Beispiel Compose-Ausschnitt:

```yaml
services:
  mcp-oauth-gateway:
    env_file: /pfad/zu/secrets/mcp-oauth-gateway.env   # Master-Key, Bootstrap-Passwort
    environment:
      MCP_GATEWAY_ROUTE_SECRETS_FILE: /run/gateway-secrets/routes.env
    volumes:
      - /pfad/zu/secrets/gateway-routen.env:/run/gateway-secrets/routes.env:ro
```

## Rotation

1. Wert in Infisical ändern.
2. Agent schreibt die Datei beim nächsten Abfrageintervall (oder sofort nach einem Agent-Neustart). Das Gateway übernimmt nach höchstens zwei Reload-Intervallen.
3. Den MCP-Server, der den Wert ebenfalls nutzt, neu erstellen (`docker compose up -d --force-recreate <dienst>`), weil `env_file` nur beim Erstellen gelesen wird.

Zwischen Schritt 2 und 3 antwortet der Upstream für einige Sekunden mit 401.

## Hinweise

- **Master-Key nicht rotieren:** `MCP_GATEWAY_AUTH_MASTER_KEY` verschlüsselt den Auth-Store. Ein neuer Wert macht alle gespeicherten Nutzer, Clients und Secrets unlesbar.
- **Bootstrap-Admin:** `MCP_GATEWAY_BOOTSTRAP_EMAIL` und `MCP_GATEWAY_BOOTSTRAP_PASSWORD` müssen beide gesetzt oder beide leer sein, sonst startet das Gateway nicht. Das Passwort wird nur genutzt, solange der Admin im Auth-Store fehlt. Es darf wie die anderen Werte im Secret-Manager liegen.
- **Rückweg:** Schlüssel aus der Datei entfernen (das Gateway fällt auf den Auth-Store zurück) oder `MCP_GATEWAY_ROUTE_SECRETS_FILE` leeren und das Gateway neu erstellen. Vor jeder Umstellung `routes.yaml` und `auth-store.enc` gemeinsam sichern.
