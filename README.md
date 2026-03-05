# SD-JWT Selective Disclosure — Proof of Concept

> Universitärer Proof of Concept (DHBW TIF23A) zur Demonstration von **Selective Disclosure Verifiable Credentials** basierend auf dem [IETF SD-JWT Standard](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/).

## Überblick

Dieses Projekt implementiert ein vollständiges **SD-JWT Verifiable Credential System** mit drei Komponenten:

| Komponente | Rolle | Beschreibung |
|------------|-------|--------------|
| **Issuer** | Aussteller | Stellt signierte SD-JWT Credentials aus (z. B. digitaler Personalausweis) |
| **Wallet** | Inhaber | Empfängt, speichert und präsentiert Credentials selektiv |
| **Verifier** | Prüfstelle | Verifiziert präsentierte Credentials und extrahiert freigegebene Claims |

### Kerntechnologien

- **Sprache:** Python 3.10+
- **Framework:** Flask (REST API)
- **Kryptografie:** Ed25519 (EdDSA) Signaturen, SHA-256 Hashing
- **UI:** Terminal-basiert mit [Rich](https://github.com/Textualize/rich)

---

## Architektur

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│     ISSUER      │     │     WALLET      │     │    VERIFIER     │
│   (Behörde)     │     │    (Bürger)     │     │  (Prüfstelle)   │
│                 │     │                 │     │                 │
│   Port: 5001    │     │  Terminal App   │     │   Port: 5002    │
│   Flask Server  │     │  Python CLI     │     │   Flask Server  │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │  ① Credential Request │                       │
         │◄──────────────────────│                       │
         │                       │                       │
         │  ② SD-JWT +           │                       │
         │──── Disclosures ─────►│                       │
         │                       │                       │
         │                       │  ③ Präsentation       │
         │                       │─────────────────────► │
         │                       │                       │
         │  ④ Status Check       │  ⑤ Ergebnis           │
         │◄──────────────────────│◄───────────────────── │
```

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

Jede Komponente in einem eigenen Terminal starten:

```powershell
# Terminal 1 — Issuer
cd .\POC
python .\issuer.py

# Terminal 2 — Verifier
cd .\POC
python .\verifier.py

# Terminal 3 — Wallet
cd .\POC
python .\wallet.py
```

> Beim **ersten Start** jeder Komponente wird automatisch ein interaktiver **Setup-Wizard** ausgeführt.

---

## Verwendung

### Credential ausstellen (Issuer → Wallet)

1. **Issuer:** `offer 1234-CODE` — Credential-Angebot erstellen
2. **Wallet:** `receive` — Pre-Authorized Code eingeben
3. Das Credential wird automatisch in der Wallet gespeichert

### Credential präsentieren (Wallet → Verifier)

1. **Wallet:** `present` — Credential und Claims selektiv auswählen
2. **Verifier:** zeigt die verifizierten Daten an

### Credential widerrufen

```
issuer> revoke 0
```

---

## Gehostete Instanzen

| Dienst | URL |
|--------|-----|
| **Illuminati Issuer** | `http://sd-issuer.ltm-labs.de:5001` |
| **Tinhat Verifier** | `http://sd-verifier.ltm-labs.de:5002` |

Diese Instanzen können direkt aus der Wallet heraus angesprochen werden, indem die URL beim `receive`- bzw. `present`-Befehl angegeben wird.

---

## Tools

### Konfiguration verwalten

```powershell
python .\config_manager.py help
```

```powershell
# Konfiguration anzeigen
python .\config_manager.py show issuer
python .\config_manager.py show verifier
python .\config_manager.py show wallet

# Konfiguration zurücksetzen
python .\config_manager.py reset issuer
```

### Zertifikatsverwaltung

```powershell
python .\cert_manager.py help
```

```powershell
# Selbstsigniertes Zertifikat (Entwicklung)
python .\cert_manager.py self-sign

# Let's Encrypt mit Cloudflare (Produktion)
python .\cert_manager.py setup
python .\cert_manager.py issue
python .\cert_manager.py status
```

---

## CLI-Befehle

<details>
<summary><strong>Issuer</strong></summary>

| Befehl | Beschreibung |
|--------|--------------|
| `offer <code>` | Credential-Angebot erstellen |
| `list` | Alle Bürger anzeigen |
| `revoke <index>` | Credential widerrufen |
| `status` | Server-Status |
| `help` | Hilfe |

</details>

<details>
<summary><strong>Wallet</strong></summary>

| Befehl | Beschreibung |
|--------|--------------|
| `receive` | Credential empfangen |
| `present` | Credential präsentieren |
| `list` | Gespeicherte Credentials |
| `delete` | Credential löschen |
| `keys` | Schlüssel anzeigen |
| `help` | Hilfe |

</details>

<details>
<summary><strong>Verifier</strong></summary>

| Befehl | Beschreibung |
|--------|--------------|
| `request` | Verification Request erstellen |
| `challenges` | Offene Challenges anzeigen |
| `clear` | Abgelaufene Challenges löschen |
| `status` | Server-Status |
| `help` | Hilfe |

</details>

---

## Projektstruktur

```
POC/
├── issuer.py              # Issuer Server (Behörde)
├── wallet.py              # Wallet Client (Bürger)
├── verifier.py            # Verifier Server (Prüfstelle)
├── sd_jwt_utils.py        # Shared Krypto-Library
├── log_manager.py         # Live-Inspection Logging
├── logger_config.py       # Logger-Konfiguration
├── config_manager.py      # Konfigurationsverwaltung mit Setup-Wizard
├── cert_manager.py        # ACME/Let's Encrypt Zertifikate
├── citizen_db.json        # Demo-Bürgerdatenbank
├── trusted_registry.json  # Trust Registry (vertrauenswürdige Issuer)
├── requirements.txt       # Python-Abhängigkeiten
└── configs/               # Generierte Konfigurationsdateien
```

---

## Features

- **Selective Disclosure** — Nur ausgewählte Claims freigeben (z. B. Alter ohne Adresse)
- **Key Binding** — Holder beweist Besitz des Credentials via Ed25519 Signatur
- **Trust Registry** — Verifier prüft Issuer gegen `trusted_registry.json`
- **Decoy Hashes** — Fake-Hashes verhindern Credential-Profiling
- **Revocation** — Credentials können vom Issuer widerrufen werden
- **Live-Inspection Mode** — Visualisierung aller internen Krypto-Operationen
- **Short-Codes** — 6-stellige Codes als Alternative zu langen URLs
- **Consent Screen** — Explizite Zustimmung vor Datenweitergabe

---

## Dokumentation

Ausführliche Dokumentation befindet sich unter [`DOKUMENTATION/POC/`](DOKUMENTATION/POC/):

- [Schnellstart](DOKUMENTATION/POC/SCHNELLSTART.md)
- [Technische Dokumentation](DOKUMENTATION/POC/DOKUMENTATION.md)
- [Architektur](DOKUMENTATION/POC/ARCHITEKTUR_TECHNISCH.md)

---

## Lizenz

Universitäres Projekt — DHBW TIF23A, Neue Konzepte der Informatik.
