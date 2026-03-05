# SD-JWT VC — Proof of Concept

> Implementierung eines **Selective Disclosure Verifiable Credential Systems** basierend auf dem SD-JWT Standard (IETF).

---

## Schnellstart

### Voraussetzungen

- Python 3.10+
- 3 Terminal-Fenster

### Installation

```powershell
cd .\POC
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Starten

Jede Komponente in einem separaten Terminal starten:

```powershell
# Terminal 1 — Issuer
python .\issuer.py

# Terminal 2 — Verifier
python .\verifier.py

# Terminal 3 — Wallet
python .\wallet.py
```

> Beim **ersten Start** wird automatisch ein interaktiver Setup-Wizard ausgeführt.

---

## Gehostete Instanzen

| Dienst | URL |
|--------|-----|
| **Illuminati Issuer** | `http://sd-issuer.ltm-labs.de:5001` |
| **Tinhat Verifier** | `http://sd-verifier.ltm-labs.de:5002` |

---

## Komponenten

| Datei | Beschreibung |
|-------|--------------|
| `issuer.py` | Issuer Server — stellt signierte SD-JWT Credentials aus |
| `wallet.py` | Wallet Client — empfängt, speichert und präsentiert Credentials |
| `verifier.py` | Verifier Server — prüft Signaturen und extrahiert Claims |
| `sd_jwt_utils.py` | Shared Library — Krypto-Funktionen (Ed25519, SHA-256) |
| `log_manager.py` | Live-Inspection Logging |
| `logger_config.py` | Logger-Konfiguration |
| `config_manager.py` | Konfigurationsverwaltung mit First-Run Setup |
| `cert_manager.py` | ACME/Let's Encrypt Zertifikatsverwaltung |
| `citizen_db.json` | Demo-Bürgerdatenbank (4 Testpersonen) |
| `trusted_registry.json` | Trust Registry — vertrauenswürdige Issuer |
| `requirements.txt` | Python-Abhängigkeiten |
| `configs/` | Generierte Konfigurationsdateien (pro Komponente) |

---

## Verwendung

### Credential ausstellen (Issuer → Wallet)

1. **Issuer:** `offer 1234-CODE` — Credential-Angebot erstellen
2. **Wallet:** `receive` — Pre-Authorized Code eingeben
3. Credential wird automatisch gespeichert

### Credential präsentieren (Wallet → Verifier)

1. **Wallet:** `present` — Credential und Claims selektiv auswählen
2. **Verifier:** zeigt verifizierte Daten an

### Credential widerrufen

```
issuer> revoke 0
```

---

## CLI-Befehle

### Issuer

| Befehl | Beschreibung |
|--------|--------------|
| `offer <code>` | Credential-Angebot erstellen |
| `list` | Alle Bürger anzeigen |
| `revoke <index>` | Credential widerrufen |
| `status` | Server-Status |
| `help` | Hilfe |

### Wallet

| Befehl | Beschreibung |
|--------|--------------|
| `receive` | Credential empfangen |
| `present` | Credential präsentieren |
| `list` | Gespeicherte Credentials |
| `delete` | Credential löschen |
| `keys` | Schlüssel anzeigen |
| `help` | Hilfe |

### Verifier

| Befehl | Beschreibung |
|--------|--------------|
| `request` | Verification Request erstellen |
| `challenges` | Offene Challenges anzeigen |
| `clear` | Abgelaufene Challenges löschen |
| `status` | Server-Status |
| `help` | Hilfe |

---

## Tools

### Konfiguration

```powershell
python .\config_manager.py help

# Beispiele
python .\config_manager.py show issuer
python .\config_manager.py show verifier
python .\config_manager.py show wallet
python .\config_manager.py reset issuer
```

### Zertifikate

```powershell
python .\cert_manager.py help

# Selbstsigniert (Entwicklung)
python .\cert_manager.py self-sign

# Let's Encrypt mit Cloudflare (Produktion)
python .\cert_manager.py setup
python .\cert_manager.py issue
python .\cert_manager.py status
```

---

## Ports

| Komponente | Standard-Port |
|------------|---------------|
| Issuer | `5001` |
| Verifier | `5002` |

---

## Konfiguration

Jede Komponente hat eine eigene Konfigurationsdatei in `configs/`:

| Komponente | Datei |
|------------|-------|
| Issuer | `configs/issuer_config.json` |
| Verifier | `configs/verifier_config.json` |
| Wallet | `configs/wallet_config.json` |

Die Konfiguration wird beim ersten Start über den Setup-Wizard erstellt und kann anschließend manuell oder per `config_manager.py` angepasst werden.

---

## Features

- **Selective Disclosure** — Nur ausgewählte Claims freigeben
- **Key Binding** — Holder-Besitznachweis via Ed25519
- **Trust Registry** — Verifier prüft Issuer gegen `trusted_registry.json`
- **Decoy Hashes** — Fake-Hashes gegen Credential-Profiling
- **Revocation** — Credentials per Bitstring Status List widerrufen
- **Live-Inspection Mode** — Visualisierung aller Krypto-Operationen
- **Short-Codes** — 6-stellige Codes als Alternative zu langen URLs
- **Consent Screen** — Explizite Zustimmung vor Datenweitergabe
- **Clock Skew Toleranz** — 20s Puffer bei `nbf`/`exp` Validierung
- **TLS** — Selbstsigniert oder Let's Encrypt via Cloudflare DNS

---

## Hinweise

- Dies ist ein **Proof of Concept** für Bildungszwecke (DHBW TIF23A)
- HTTPS ist in der Produktionsumgebung erforderlich
- SSL-Warnungen werden für den PoC unterdrückt
- **DNS / Hostnames:** Werden beim Setup FQDNs statt IP-Adressen verwendet (z. B. `sd-issuer.ltm-labs.de`), müssen die Hostnamen auf allen beteiligten Maschinen korrekt auf die jeweiligen IPs auflösen — entweder über DNS-Einträge oder lokale `hosts`-Dateien (`/etc/hosts` bzw. `C:\Windows\System32\drivers\etc\hosts`)
