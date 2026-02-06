# SD-JWT VC Proof of Concept

Dieses Verzeichnis enthält die Implementierung eines **Selective Disclosure Verifiable Credential Systems** basierend auf dem SD-JWT Standard.

**Version 4.0** - Mit Trust Registry, Decoy Hashes, Short-Codes und Consent Screen.

## Komponenten

| Datei | Beschreibung |
|-------|--------------|
| `sd_jwt_utils.py` | Shared Library mit Krypto-Funktionen |
| `log_manager.py` | Live-Inspection Logging (V3.0) |
| `config_manager.py` | Konfigurationsverwaltung mit First-Run Setup |
| `cert_manager.py` | ACME/Let's Encrypt Zertifikate (V4.0) |
| `trusted_registry.json` | Trust Registry für Issuer (V4.0) |
| `issuer.py` | Issuer Server (Behörde) |
| `wallet.py` | Wallet Client (Bürger) |
| `verifier.py` | Verifier Server (Prüfstelle) |
| `citizen_db.json` | Demo-Bürgerdatenbank |
| `configs/` | Konfigurationsdateien (pro Komponente) |
| `requirements.txt` | Python-Abhängigkeiten |

## Schnellstart

### 1. Installation

```bash
# Virtual Environment erstellen (empfohlen)
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Abhängigkeiten installieren
pip install -r requirements.txt
```

### 2. Issuer starten (Terminal 1)

```bash
python issuer.py
```

### 3. Verifier starten (Terminal 2)

```bash
python verifier.py
```

### 4. Wallet starten (Terminal 3)

```bash
python wallet.py
```

## Typischer Ablauf

### Credential ausstellen (Issuer → Wallet)

1. **Issuer:** `offer 1234-CODE` - Erstellt ein Credential-Angebot
2. **Wallet:** `receive` - Gibt den Pre-Authorized Code ein
3. **Wallet:** Credential wird automatisch gespeichert

### Credential präsentieren (Wallet → Verifier)

1. **Wallet:** `present` - Wählt Credential und Claims aus
2. **Verifier:** Zeigt verifizierte Daten an

### Credential widerrufen (Issuer)

```
issuer> revoke 0
```

## Befehle

### Issuer
- `offer <code>` - Credential Offer erstellen
- `list` - Alle Bürger anzeigen
- `revoke <index>` - Credential widerrufen
- `status` - Server-Status
- `help` - Hilfe

### Wallet
- `receive` - Credential empfangen
- `present` - Credential präsentieren
- `list` - Gespeicherte Credentials
- `delete` - Credential löschen
- `keys` - Schlüssel anzeigen
- `help` - Hilfe

### Verifier
- `request` - Verification Request erstellen
- `challenges` - Offene Challenges anzeigen
- `clear` - Abgelaufene Challenges löschen
- `status` - Server-Status
- `help` - Hilfe

## Ports

- Issuer: `http://localhost:5001`
- Verifier: `http://localhost:5002`

## Live-Inspection Mode (Version 3.0)

Version 3.0 fügt einen **Live-Inspection Mode** hinzu, der alle internen Operationen visualisiert:

| Komponente | Modul | Zeigt an |
|------------|-------|----------|
| Issuer | Crypto-Insight | Salts, Hashes, Signaturen, Token-Struktur |
| Wallet | Traffic-Monitor | HTTP-Requests/Responses, Credential-Speicherung |
| Verifier | Verification-Logic | Prüfschritte als Checkliste, Hash-Verifikation |

Der Mode kann in der Konfigurationsdatei jeder Komponente aktiviert/deaktiviert werden:

```json
"inspection_mode": true
```

Oder beim First-Run Setup abgefragt.

## Version 4.0 Features

### Trust Registry
Der Verifier lädt vertrauenswürdige Issuer aus `trusted_registry.json` statt Hardcoding.

### Decoy Hashes
Fake-Hashes werden ins `_sd` Array gemischt, um Credential-Profiling zu verhindern:
```python
"add_decoys": True,  # In issuer.py CONFIG
"decoy_count": 2
```

### Short-Codes
4-stellige Codes als Alternative zu langen URLs:
```
Issuer  → "Short-Code: 4821"
Wallet  → "Pre-Authorized Code oder Short-Code: 4821"
```

### Consent Screen
Explizite Zustimmung mit Übersicht welche Daten geteilt/nicht geteilt werden.

### Clock Skew Toleranz
60 Sekunden Zeitpuffer bei nbf/exp Validierung für unsynchronisierte Uhren.

## Konfiguration

Jede Komponente hat eine **eigene Konfigurationsdatei** in `configs/`:

| Komponente | Konfigurationsdatei |
|------------|---------------------|
| Issuer | `configs/issuer_config.json` |
| Verifier | `configs/verifier_config.json` |
| Wallet | `configs/wallet_config.json` |

### Ersteinrichtung

Beim **ersten Start** jeder Komponente wird automatisch ein Setup-Wizard gestartet:

```
python issuer.py    # → Interaktiver Setup-Wizard für Issuer
python verifier.py  # → Interaktiver Setup-Wizard für Verifier
python wallet.py    # → Interaktiver Setup-Wizard für Wallet
```

Der Wizard fragt alle notwendigen Werte ab:
- Server-Port und URL
- TLS-Modus (selbstsigniert, Let's Encrypt, manuell)
- Komponenten-spezifische Einstellungen

### Konfiguration verwalten

```bash
# Konfiguration anzeigen
python config_manager.py issuer show
python config_manager.py verifier show
python config_manager.py wallet show

# Konfiguration zurücksetzen (löst neues Setup aus)
python config_manager.py issuer reset
```

### Manuelle Konfiguration

Die JSON-Dateien können auch manuell bearbeitet werden:

**Issuer:**
```json
{
  "issuer_name": "Bundesamt für Digitale Identität",
  "issuer_uri": "https://localhost:5001",
  "port": 5001,
  "ssl": {
    "enabled": true,
    "mode": "self-signed",
    "cert_file": "certs/issuer.crt",
    "key_file": "certs/issuer.key"
  },
  "inspection_mode": true
}
```

**Verifier:**
```json
{
  "verifier_name": "Altersverifikation Service",
  "port": 5002,
  "trusted_issuers": ["https://localhost:5001"]
}
```

**Wallet:**
```json
{
  "default_issuer": "https://localhost:5001",
  "default_verifier": "https://localhost:5002"
}
```

## TLS-Zertifikate

### Option 1: Selbstsigniert (Entwicklung)
```bash
python cert_manager.py self-sign
```
Erstellt Zertifikate für localhost - Browser zeigen Warnungen.

### Option 2: Let's Encrypt mit Cloudflare (Produktion)
```bash
# Einmalige Einrichtung
python cert_manager.py setup

# Zertifikate anfordern
python cert_manager.py issue

# Status prüfen
python cert_manager.py status
```

Benötigt:
- Cloudflare API Token (Zone:DNS:Edit)
- Echte Domain mit Cloudflare DNS

Funktioniert auf **Windows und Linux** - komplett Python-nativ.

## Hinweise

- Dies ist ein **Proof of Concept** für Bildungszwecke
- HTTPS ist in der Produktionsumgebung erforderlich
- SSL-Warnungen werden für den PoC unterdrückt
