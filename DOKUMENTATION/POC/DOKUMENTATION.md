# SD-JWT Verifiable Credentials - Proof of Concept Dokumentation

## Inhaltsverzeichnis

1. [Einführung](#1-einführung)
2. [Architektur-Übersicht](#2-architektur-übersicht)
3. [Technische Grundlagen](#3-technische-grundlagen)
4. [Komponenten im Detail](#4-komponenten-im-detail)
5. [Datenflüsse](#5-datenflüsse)
6. [API-Referenz](#6-api-referenz)
7. [Installation & Betrieb](#7-installation--betrieb)
8. [Sicherheitsbetrachtungen](#8-sicherheitsbetrachtungen)
9. [Standards & Referenzen](#9-standards--referenzen)
10. [Version 3.0: Live-Inspection Mode](#10-version-30-live-inspection-mode)
11. [Version 4.0: Robustheit & Usability](#11-version-40-robustheit--usability)
12. [Version 5.0: Deep-Trace File-Logging](#12-version-50-deep-trace-file-logging)
13. [Version 6.0: CLI Certificate Renewal](#13-version-60-cli-certificate-renewal)
14. [Version 7.0: Usability & Hardening](#14-version-70-usability--hardening)
15. [Weiterführende Dokumentation](#15-weiterführende-dokumentation)

---

## 1. Einführung

### 1.1 Was ist Selective Disclosure?

**Selective Disclosure** ermöglicht es dem Inhaber eines digitalen Ausweises (Verifiable Credential), nur ausgewählte Informationen an einen Verifier preiszugeben, anstatt das gesamte Credential offenzulegen.

**Beispiel:** Bei einer Alterskontrolle muss nur das Geburtsdatum oder ein "über 18"-Flag gezeigt werden – nicht der vollständige Name oder die Adresse.

### 1.2 Was ist ein SD-JWT?

Ein **SD-JWT (Selective Disclosure JWT)** ist ein standardisiertes Token-Format gemäß dem IETF-Entwurf, das Selective Disclosure ermöglicht. Es besteht aus:

1. **Issuer-signiertem JWT** - Enthält Hash-Digest der Claims
2. **Disclosures** - Separate Base64-codierte Claim-Werte
3. **Key Binding JWT** - Beweis des Holder-Besitzes

### 1.3 Projektziel

Dieser Proof of Concept demonstriert eine vollständige Implementierung des SD-JWT-Standards mit:
- Pre-Authorized Code Flow (OID4VCI)
- Selective Disclosure bei der Präsentation
- Revocation via Bitstring Status List
- Terminal-basierte Benutzeroberfläche

---

## 2. Architektur-Übersicht

### 2.1 Systemkomponenten

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│     ISSUER      │     │     WALLET      │     │    VERIFIER     │
│  (Behörde)      │     │   (Bürger)      │     │  (Prüfstelle)   │
│                 │     │                 │     │                 │
│  Port: 5001     │     │  Terminal App   │     │  Port: 5002     │
│  Flask Server   │     │  Python CLI     │     │  Flask Server   │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │    ①  Credential      │                       │
         │◄──── Request ─────────│                       │
         │                       │                       │
         │    ②  SD-JWT +        │                       │
         │─────  Disclosures ───►│                       │
         │                       │                       │
         │                       │    ③  Präsentation    │
         │                       │─────────────────────►│
         │                       │                       │
         │    ④  Status Check    │    ⑤  Ergebnis       │
         │◄──────────────────────│◄─────────────────────│
         │                       │                       │
```

### 2.2 Dateistruktur

```
POC/
├── sd_jwt_utils.py      # Kryptografische Funktionen
├── log_manager.py       # Version 3.0: Live-Inspection Logging
├── logger_config.py     # Version 5.0: Deep-Trace File-Logging
├── config_manager.py    # Konfigurationsverwaltung mit First-Run Setup
├── cert_manager.py      # Version 6.0: ACME/Let's Encrypt Zertifikate
├── issuer.py            # Issuer Server
├── wallet.py            # Wallet Client  
├── verifier.py          # Verifier Server
├── citizen_db.json      # Simulierte Bürgerdatenbank
├── issuer_keys.json     # Issuer-Schlüssel (generiert)
├── wallet_store.json    # Wallet-Speicher (generiert)
├── trusted_registry.json# Trust Registry für Verifier
├── requirements.txt     # Python-Abhängigkeiten
├── README.md            # Kurzanleitung
├── ARCHITECTURE.md      # Architektur-Plan
├── configs/             # Komponenten-Konfigurationen
│   ├── issuer_config.json
│   ├── verifier_config.json
│   └── wallet_config.json
└── logs/                # Debug-Logdateien (v5.0)
    ├── issuer_debug.log
    ├── wallet_debug.log
    └── verifier_debug.log
```

---

## 3. Technische Grundlagen

### 3.1 Kryptografische Algorithmen

| Zweck | Algorithmus | Bibliothek |
|-------|-------------|------------|
| Signaturen | Ed25519 (EdDSA) | `cryptography` |
| Hashing | SHA-256 | Python `hashlib` |
| Encoding | Base64 URL-safe | Python `base64` |

### 3.2 SD-JWT Token-Struktur

Ein SD-JWT besteht aus drei Teilen:

#### Header
```json
{
  "alg": "EdDSA",
  "typ": "sd+jwt"
}
```

#### Payload
```json
{
  "iss": "https://issuer.example.com",
  "sub": "citizen:1234-CODE",
  "iat": 1707235200,
  "exp": 1738771200,
  "_sd": [
    "abc123...",  // Hash von Disclosure 1
    "def456...",  // Hash von Disclosure 2
    "..."
  ],
  "_sd_alg": "sha-256",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "holder-public-key-base64"
    }
  },
  "status": {
    "status_list": {
      "idx": 0,
      "uri": "https://issuer.example.com/status"
    }
  }
}
```

#### Disclosures (separate Strings)
```
WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIk1heCJd
```
(Base64 von: `["salt", "given_name", "Max"]`)

### 3.3 Key Binding JWT

Der **KB-JWT** beweist, dass der Präsentierende den Private Key besitzt, der zum `cnf` Claim gehört:

```json
{
  "alg": "EdDSA",
  "typ": "kb+jwt"
}
.
{
  "iat": 1707235200,
  "aud": "https://verifier.example.com",
  "nonce": "random-challenge",
  "sd_hash": "hash-of-sd-jwt"
}
```

---

## 4. Komponenten im Detail

### 4.1 Shared Library (`sd_jwt_utils.py`)

Die zentrale Bibliothek stellt folgende Funktionen bereit:

#### Key Management
```python
generate_ed25519_keypair()  # Erstellt Schlüsselpaar
load_private_key(bytes)     # Lädt Private Key
load_public_key(bytes)      # Lädt Public Key
key_to_base64(bytes)        # Konvertiert zu Base64
base64_to_key(str)          # Konvertiert von Base64
```

#### JWT Operationen
```python
sign_jwt(header, payload, key)        # Signiert JWT
verify_jwt_signature(jwt, pub_key)    # Prüft Signatur
get_jwt_payload(jwt)                  # Extrahiert Payload
get_jwt_header(jwt)                   # Extrahiert Header
```

#### Disclosure Management
```python
create_disclosure(name, value)  # Erstellt Disclosure + Hash
decode_disclosure(encoded)      # Decodiert Disclosure
hash_disclosure(encoded)        # Berechnet Hash
```

#### SD-JWT Erstellung
```python
create_sd_jwt(
    claims,              # Dict mit Claim-Werten
    issuer_private_key,  # Issuer Key
    holder_public_key,   # Holder Key für cnf
    issuer,              # Issuer URI
    subject,             # Subject ID
    status_index,        # Optional: Revocation Index
    status_uri           # Optional: Status List URI
)
# Gibt zurück: (sd_jwt, disclosures, disclosure_map)
```

#### Key Binding
```python
create_kb_jwt(sd_jwt, holder_key, audience, nonce)
verify_kb_jwt(kb_jwt, sd_jwt, holder_pub_key, aud, nonce)
```

#### Status List (Revocation)
```python
create_status_list(size)          # Neue Bitstring-Liste
get_status(list, index)           # Prüft Status
set_status(list, index, revoked)  # Setzt Status
```

### 4.2 Issuer Server (`issuer.py`)

#### Funktionen
- Lädt Bürgerdatenbank aus `citizen_db.json`
- Generiert und speichert Issuer-Schlüssel
- Verwaltet Bitstring Status List für Revocation
- Erstellt Pre-Authorized Code Offers
- Stellt SD-JWT Credentials aus

#### Terminal-Befehle
| Befehl | Beschreibung |
|--------|--------------|
| `offer <code>` | Erstellt Credential-Angebot mit QR-Code |
| `list` | Zeigt alle Bürger in der Datenbank |
| `revoke <index>` | Widerruft ein Credential |
| `status` | Server-Status anzeigen |
| `help` | Hilfe anzeigen |

#### Endpunkte
| Route | Methode | Beschreibung |
|-------|---------|--------------|
| `/.well-known/openid-credential-issuer` | GET | Issuer Metadata |
| `/token` | POST | Access Token anfordern |
| `/credential` | POST | Credential anfordern |
| `/status` | GET | Status List abrufen |
| `/health` | GET | Health Check |

### 4.3 Wallet Client (`wallet.py`)

#### Funktionen
- Generiert und speichert Ed25519 Schlüsselpaar
- Empfängt Credentials via Pre-Authorized Code Flow
- Speichert Credentials in `wallet_store.json`
- Ermöglicht selektive Claim-Auswahl bei Präsentation
- Erstellt Key Binding JWT für Präsentationen

#### Terminal-Befehle
| Befehl | Beschreibung |
|--------|--------------|
| `receive` | Credential vom Issuer empfangen |
| `present` | Credential an Verifier präsentieren |
| `list` | Gespeicherte Credentials anzeigen |
| `delete` | Credential löschen |
| `keys` | Wallet-Schlüssel anzeigen |
| `help` | Hilfe anzeigen |

### 4.4 Verifier Server (`verifier.py`)

#### Funktionen
- Generiert Challenges (Nonces) für Präsentationen
- Validiert SD-JWT Signaturen
- Prüft Disclosure-Hashes
- Verifiziert Key Binding JWT
- Prüft Revocation-Status beim Issuer

#### Verifikationsschritte
1. Präsentation parsen
2. Issuer-Vertrauenswürdigkeit prüfen (Trust Registry v4.0)
3. Issuer Public Key abrufen
4. SD-JWT Signatur verifizieren
5. Disclosure-Hashes validieren
6. Holder Public Key extrahieren
7. Nonce-Gültigkeit prüfen
8. KB-JWT Signatur verifizieren
9. SD-Hash überprüfen (KB-JWT bindet an SD-JWT)
10. Zeit-Claims prüfen (mit Clock Skew Toleranz)
11. Revocation-Status prüfen

#### Terminal-Befehle
| Befehl | Beschreibung |
|--------|--------------|
| `request` | Verification Request mit QR-Code |
| `challenges` | Offene Challenges anzeigen |
| `clear` | Abgelaufene Challenges löschen |
| `status` | Server-Status anzeigen |
| `help` | Hilfe anzeigen |

---

## 5. Datenflüsse

### 5.1 Credential Issuance Flow

```
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│  ISSUER  │                    │  WALLET  │                    │  USER    │
└────┬─────┘                    └────┬─────┘                    └────┬─────┘
     │                               │                               │
     │◄────── offer 1234-CODE ───────│                               │
     │                               │                               │
     │  Pre-Auth Code + QR anzeigen  │                               │
     │──────────────────────────────►│                               │
     │                               │                               │
     │                               │◄──── Code eingeben ───────────│
     │                               │                               │
     │◄───── POST /token ────────────│                               │
     │        {pre-auth code}        │                               │
     │                               │                               │
     │  Access Token + c_nonce       │                               │
     │──────────────────────────────►│                               │
     │                               │                               │
     │  Generiere Proof-of-Possession│                               │
     │  (JWT mit Wallet-Key signiert)│                               │
     │                               │                               │
     │◄───── POST /credential ───────│                               │
     │        {proof, token}         │                               │
     │                               │                               │
     │  Erstelle SD-JWT              │                               │
     │  - Hash Claims → _sd Array    │                               │
     │  - cnf = Wallet Public Key    │                               │
     │  - Signiere mit Issuer Key    │                               │
     │                               │                               │
     │  SD-JWT + Disclosures         │                               │
     │──────────────────────────────►│                               │
     │                               │                               │
     │                               │  Speichere in wallet_store.json│
     │                               │──────────────────────────────►│
     │                               │                               │
```

### 5.2 Credential Presentation Flow

```
┌──────────┐                    ┌──────────┐                    ┌──────────┐
│ VERIFIER │                    │  WALLET  │                    │  ISSUER  │
└────┬─────┘                    └────┬─────┘                    └────┬─────┘
     │                               │                               │
     │◄───── GET /challenge ─────────│                               │
     │                               │                               │
     │  nonce + audience             │                               │
     │──────────────────────────────►│                               │
     │                               │                               │
     │                               │  User wählt Claims aus        │
     │                               │  [1] given_name ✓             │
     │                               │  [2] birthdate ✓              │
     │                               │  [3] address ✗                │
     │                               │                               │
     │                               │  Erstelle KB-JWT              │
     │                               │  - aud = verifier             │
     │                               │  - nonce = challenge          │
     │                               │  - sd_hash = hash(sd_jwt)     │
     │                               │  - Signiere mit Wallet Key    │
     │                               │                               │
     │◄───── POST /verify ───────────│                               │
     │  SD-JWT~Disc1~Disc2~KB-JWT    │                               │
     │                               │                               │
     │  1. Parse Präsentation        │                               │
     │  2. Prüfe Issuer Trust        │                               │
     │                               │                               │
     │◄───────────────── GET /.well-known/openid-credential-issuer ──│
     │                               │                               │
     │──────────────────── Issuer Public Key ───────────────────────►│
     │                               │                               │
     │  3. Verifiziere SD-JWT Signatur                               │
     │  4. Hash Disclosures          │                               │
     │  5. Prüfe Hashes in _sd Array │                               │
     │  6. Verifiziere KB-JWT        │                               │
     │                               │                               │
     │◄───────────────────────────── GET /status ────────────────────│
     │                               │                               │
     │────────────────────────────── Status List ───────────────────►│
     │                               │                               │
     │  7. Prüfe Revocation-Status   │                               │
     │                               │                               │
     │  ✓ VALID                      │                               │
     │  Claims: given_name, birthdate│                               │
     │──────────────────────────────►│                               │
     │                               │                               │
```

---

## 6. API-Referenz

### 6.1 Issuer API

#### GET `/.well-known/openid-credential-issuer`
Liefert die Issuer-Metadaten.

**Response:**
```json
{
  "issuer": "https://issuer.example.com",
  "credential_issuer": "https://issuer.example.com",
  "credential_endpoint": "https://issuer.example.com/credential",
  "token_endpoint": "https://issuer.example.com/token",
  "status_list_endpoint": "https://issuer.example.com/status",
  "jwks": {
    "keys": [{
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "base64-public-key"
    }]
  },
  "credentials_supported": [{
    "format": "sd_jwt_vc",
    "type": "IdentityCredential"
  }]
}
```

#### POST `/token`
Tauscht Pre-Authorized Code gegen Access Token.

**Request:**
```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
  "pre-authorized_code": "abc123..."
}
```

**Response:**
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 600,
  "c_nonce": "xyz789...",
  "c_nonce_expires_in": 300
}
```

#### POST `/credential`
Fordert ein Credential an.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{
  "format": "sd_jwt_vc",
  "proof": {
    "proof_type": "jwt",
    "jwt": "eyJ..."
  }
}
```

**Response:**
```json
{
  "format": "sd_jwt_vc",
  "credential": "eyJ...~WyJ...",
  "disclosures": ["WyJ...", "WyJ..."],
  "disclosure_mapping": {
    "given_name": "WyJ...",
    "birthdate": "WyJ..."
  }
}
```

#### GET `/status`
Liefert die Revocation Status List.

**Response:**
```json
{
  "status_list": "base64-compressed-bitstring",
  "bits": 1,
  "size": 1000
}
```

### 6.2 Verifier API

#### GET `/challenge`
Generiert eine Challenge für die Präsentation.

**Response:**
```json
{
  "nonce": "random-nonce",
  "state": "random-state",
  "audience": "https://verifier.example.com",
  "expires_in": 300
}
```

#### POST `/verify`
Verifiziert eine Präsentation.

**Request:**
```json
{
  "presentation": "<SD-JWT>~<Disclosure1>~<Disclosure2>~<KB-JWT>"
}
```

**Response (Erfolg):**
```json
{
  "valid": true,
  "issuer": "https://issuer.example.com",
  "claims": {
    "given_name": "Max",
    "birthdate": "1990-01-15"
  },
  "holder_verified": true,
  "status": "Credential aktiv (Index 0)"
}
```

**Response (Fehler):**
```json
{
  "valid": false,
  "error": "Invalid issuer signature"
}
```

---

## 7. Installation & Betrieb

### 7.1 Voraussetzungen

- Python 3.10 oder höher
- pip (Python Package Manager)

### 7.2 Installation

```bash
# Repository klonen
cd POC

# Virtual Environment erstellen
python -m venv venv

# Aktivieren
venv\Scripts\activate      # Windows
# source venv/bin/activate # Linux/Mac

# Abhängigkeiten installieren
pip install -r requirements.txt
```

### 7.3 Server starten

**Terminal 1 - Issuer:**
```bash
python issuer.py
```

**Terminal 2 - Verifier:**
```bash
python verifier.py
```

**Terminal 3 - Wallet:**
```bash
python wallet.py
```

### 7.4 Typischer Demo-Ablauf

1. **Issuer:** Credential-Angebot erstellen
   ```
   issuer> offer 1234-CODE
   ```

2. **Wallet:** Credential empfangen
   ```
   wallet> receive
   Issuer URL [http://localhost:5001]: 
   Pre-Authorized Code: <Code von Issuer einfügen>
   ```

3. **Wallet:** Credential präsentieren
   ```
   wallet> present
   Verifier URL [http://localhost:5002]:
   Wähle Claims: 1,2  # z.B. given_name und birthdate
   ```

4. **Verifier:** Zeigt verifizierte Daten an

### 7.5 HTTPS-Konfiguration (Produktion)

Für den Produktionsbetrieb sind SSL-Zertifikate erforderlich:

```bash
# Zertifikate erstellen (self-signed für Tests)
mkdir certs
openssl req -x509 -newkey rsa:4096 -keyout certs/issuer.key \
  -out certs/issuer.crt -days 365 -nodes

openssl req -x509 -newkey rsa:4096 -keyout certs/verifier.key \
  -out certs/verifier.crt -days 365 -nodes
```

Für Let's Encrypt Zertifikate:
```bash
certbot certonly --dns-cloudflare \
  -d issuer.example.com \
  --dns-cloudflare-credentials ~/.cloudflare.ini
```

---

## 8. Sicherheitsbetrachtungen

### 8.1 Implementierte Sicherheitsmaßnahmen

| Maßnahme | Beschreibung |
|----------|--------------|
| Ed25519 | Moderne, sichere Elliptic-Curve-Signatur |
| Key Binding | Holder muss Besitz des Private Keys beweisen |
| Nonce-basierte Challenge | Verhindert Replay-Attacken |
| SD-Hash in KB-JWT | Bindet KB-JWT an spezifisches SD-JWT |
| Revocation via Status List | Ermöglicht nachträglichen Widerruf |

### 8.2 PoC-Limitierungen

| Aspekt | Status | Produktionsempfehlung |
|--------|--------|----------------------|
| HTTPS | Optional | Erforderlich |
| Key Storage | Klartext JSON | HSM oder Secure Enclave |
| Token Expiry | Einfache Zeitprüfung | Token Blacklisting |
| Rate Limiting | Nicht implementiert | Erforderlich |
| Input Validation | Basis | Umfassend erweitern |

### 8.3 Bedrohungsmodell

**Geschützt gegen:**
- Credential-Fälschung (Signaturprüfung)
- Unbefugte Nutzung (Key Binding)
- Replay-Attacken (Nonce)
- Komplette Offenlegung (Selective Disclosure)
- Nutzung widerrufener Credentials (Status List)

**Nicht geschützt gegen (im PoC):**
- Man-in-the-Middle ohne HTTPS
- Kompromittierung des Wallet-Geräts
- Social Engineering

---

## 9. Standards & Referenzen

### 9.1 Implementierte Standards

| Standard | Beschreibung | Link |
|----------|--------------|------|
| SD-JWT | Selective Disclosure JWT | [IETF Draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) |
| OID4VCI | OpenID for Verifiable Credential Issuance | [OpenID](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) |
| OID4VP | OpenID for Verifiable Presentations | [OpenID](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) |
| Ed25519 | Edwards-Curve Digital Signature | [RFC 8032](https://tools.ietf.org/html/rfc8032) |

### 9.2 Weiterführende Ressourcen

- [Walt.id Documentation](https://docs.walt.id/concepts)
- [SD-JWT Concepts](https://docs.walt.id/concepts/digital-credentials/sd-jwt-vc)
- [Selective Disclosure](https://docs.walt.id/concepts/selective-disclosure)
- [Credential Status](https://docs.walt.id/concepts/credential-lifecycle/credential-status-and-revocation)
- [OpenID4VCI](https://docs.walt.id/concepts/data-exchange-protocols/openid4vci)
- [OpenID4VP](https://docs.walt.id/concepts/data-exchange-protocols/openid4vp)

### 9.3 Bibliotheken

| Bibliothek | Version | Verwendung |
|------------|---------|------------|
| Flask | ≥2.3.0 | REST API Server |
| cryptography | ≥41.0.0 | Ed25519 Kryptografie |
| rich | ≥13.0.0 | Terminal UI |
| segno | ≥1.6.0 | QR-Code Generierung |
| requests | ≥2.31.0 | HTTP Client |

---

## Changelog

| Version | Datum | Änderungen |
|---------|-------|------------|
| 1.0 | 2025-11-03 | Initiale Implementierung |
| 3.0 | 2025-11-05 | Live-Inspection Mode (Crypto-Insight, Traffic-Monitor, Verification-Logic) |
| 4.0 | 2025-11-06 | Trust Registry, Clock Skew Toleranz, Decoy Hashes, Short-Codes, Consent Screen |
| 5.0 | 2025-11-07 | Deep-Trace File-Logging (persistente Logdateien) |
| 6.0 | 2025-11 | CLI Certificate Renewal, cert_manager.py, config_manager.py |
| 7.0 | 2025-11 | Short-Codes auf 6 Stellen erweitert, Clock Skew auf 20s reduziert, Hilfe beim Start, Server-Ready-Check |
---

## 10. Version 3.0: Live-Inspection Mode

### 10.1 Übersicht

Version 3.0 führt den **Live-Inspection Mode** ein, der alle kryptografischen Operationen, Netzwerkkommunikation und Verifikationsschritte in Echtzeit visualisiert. Dies dient Bildungszwecken und ermöglicht ein tiefes Verständnis der SD-JWT-Prozesse.

### 10.2 Komponenten

#### 10.2.1 Crypto-Insight (Issuer)

Visualisiert die Kryptografie bei der Credential-Ausstellung:

| Funktion | Anzeige |
|----------|---------|
| `show_raw_data()` | Rohdaten vor der Verarbeitung |
| `show_salting()` | Salt-Werte für Disclosures |
| `show_hashing()` | SHA-256 Hash-Berechnung |
| `show_token_structure()` | JWT Header, Payload, Signature |
| `show_signature()` | EdDSA-Signaturprozess |
| `show_status_list_update()` | Bitstring Status List Änderungen |

#### 10.2.2 Traffic-Monitor (Wallet)

Zeigt die Netzwerkkommunikation:

| Funktion | Anzeige |
|----------|---------|
| `show_outgoing_request()` | HTTP-Anfragen mit Header/Body |
| `show_incoming_response()` | Server-Antworten mit Status |
| `show_credential_storage()` | Lokale Speicherung |
| `show_disclosure_selection()` | Auswahl der offenzulegenden Claims |
| `show_kb_jwt_creation()` | Key Binding JWT Erstellung |
| `show_presentation_packet()` | Finales Präsentationspaket |

#### 10.2.3 Verification-Logic (Verifier)

Zeigt die Verifikationsschritte als Checkliste:

| Funktion | Anzeige |
|----------|---------|
| `show_incoming_presentation()` | Empfangene Präsentation |
| `add_check()` | Prüfschritt zur Checkliste hinzufügen |
| `show_hash_verification()` | Disclosure-Hash Verifikation |
| `show_status_check()` | Revocation Status Prüfung |
| `show_checklist()` | Finale Checkliste (✓/✗) |
| `show_extracted_claims()` | Erfolgreich extrahierte Claims |

### 10.3 Aktivierung

Der Live-Inspection Mode wird in der `CONFIG` jeder Komponente aktiviert:

```python
CONFIG = {
    # ...
    "inspection_mode": True  # Auf False setzen zum Deaktivieren
}
```

### 10.4 Beispielausgabe

**Issuer (Crypto-Insight):**
```
════════════════════════════════════════════════════════════
CRYPTO-INSIGHT MODE ACTIVE
════════════════════════════════════════════════════════════

┌─ RAW DATA ─────────────────────────────────────────────────┐
│ Claim: given_name                                          │
│ Value: Max                                                 │
└────────────────────────────────────────────────────────────┘

┌─ SALTING ──────────────────────────────────────────────────┐
│ Salt: Kj7xP2mN9qW4rT6...                                   │
│ Claim: given_name                                          │
│ Value: Max                                                 │
│ Disclosure: ["Kj7xP2mN9qW4rT6...", "given_name", "Max"]    │
│ Base64: W0tqN3hQMm1OOXFXNHJUNi4uLg==                       │
└────────────────────────────────────────────────────────────┘
```

**Verifier (Verification-Logic):**
```
════════════════════════════════════════════════════════════
VERIFICATION CHECKLIST
════════════════════════════════════════════════════════════
 ✓ Issuer vertrauenswürdig          https://localhost:5001
 ✓ Issuer Signatur (EdDSA)          Ed25519 Kurve
 ✓ Disclosure-Hashes                3 geprüft
 ✓ Nonce gültig                     aB3dE5fG7hI9jK...
 ✓ KB-JWT Signatur (Holder)         Proof of Possession
 ✓ SD-Hash Bindung                  KB-JWT bindet an SD-JWT
 ✓ Revocation Status                Nicht widerrufen
════════════════════════════════════════════════════════════
```

---

## 11. Version 4.0: Robustheit & Usability

### 11.1 Übersicht

Version 4.0 fügt Robustheitsfunktionen und verbesserte Usability hinzu:

| Feature | Beschreibung |
|---------|--------------|
| Trust Registry | Verifier lädt vertrauenswürdige Issuer aus JSON-Datei |
| Clock Skew Toleranz | 20 Sekunden Zeitpuffer bei nbf/exp Validierung |
| Decoy Hashes | Fake-Hashes gegen Credential-Profiling |
| Short-Codes | 6-stellige Codes statt langer URLs |
| Consent Screen | Explizite Zustimmung mit Datenübersicht |

### 11.2 Trust Registry

Die Datei `trusted_registry.json` simuliert eine PKI/DID-Infrastruktur:

```json
{
  "issuers": {
    "http://localhost:5001": {
      "name": "Bürgerbüro Musterstadt",
      "type": "government",
      "public_key": null,
      "fetch_from_metadata": true
    }
  }
}
```

- `public_key`: Vordefinierter Ed25519 Key (Base64)
- `fetch_from_metadata`: Key von Issuer holen wenn `null`

### 11.3 Clock Skew Toleranz

Verteilte Systeme haben oft unsynchronisierte Uhren. Version 4.0 toleriert ±20 Sekunden:

```python
CLOCK_SKEW_LEEWAY = 20  # Sekunden

def validate_time_claims(payload, leeway=CLOCK_SKEW_LEEWAY):
    # nbf: Token gültig wenn now >= nbf - leeway
    # exp: Token gültig wenn now <= exp + leeway
```

### 11.4 Decoy Hashes (Anti-Profiling)

Decoy-Hashes verschleiern die echte Anzahl der Claims:

```
_sd Array ohne Decoys: [hash1, hash2, hash3]        → 3 Claims erkennbar
_sd Array mit Decoys:  [hash1, decoy, hash2, hash3, decoy] → Anzahl verschleiert
```

- Aktivierung: `"add_decoys": true` in Issuer CONFIG
- Decoys haben keine zugehörige Disclosure
- Werden bei Validierung ignoriert

### 11.5 Short-Codes

6-stellige Codes für einfache Eingabe im Terminal statt langer URLs:

**Issuer:**
```
Pre-Authorized Code: aB3dE5fG7hI9...
Short-Code: 482193  ← Einfache Eingabe
```

**Wallet:**
```
Pre-Authorized Code oder Short-Code (6 Ziffern): 482193
→ Short-Code erkannt, löse auf...
✓ Short-Code aufgelöst
```

**API-Endpunkte:**
- `GET /shortcode/<code>` (Issuer): Gibt Offer-URI zurück
- `GET /shortcode/<code>` (Verifier): Gibt Nonce/State zurück

### 11.6 Consent Screen

Vor dem Senden wird eine klare Übersicht gezeigt:

```
┌─ ⚠️ Consent / Zustimmung ──────────────────────────────────┐
│ ACHTUNG: Datenfreigabe                                     │
│                                                             │
│ Verifier: http://localhost:5002                            │
│                                                             │
│ ✓ WIRD GETEILT:                                            │
│    • given_name: Max                                       │
│    • is_over_18: true                                      │
│                                                             │
│ ✗ WIRD NICHT GETEILT:                                      │
│    • family_name                                           │
│    • birthdate                                             │
│    • address                                               │
└────────────────────────────────────────────────────────────┘
Daten wirklich an diesen Verifier senden? [y/N]
```

---

## 12. Version 5.0: Deep-Trace File-Logging

### 12.1 Übersicht

Version 5.0 führt dateibasiertes Logging ein, um kryptografische Operationen nachvollziehbar und für Präsentationen/Debugging persistierbar zu machen.

| Feature | Beschreibung |
|---------|---------------|
| Persistente Logs | Alle Operationen werden in Dateien geschrieben |
| Komponenten-Trennung | Separate Logdateien pro Komponente |
| Debug-Tiefe | Vollständige kryptografische Details |
| Session-Reset | Logdatei wird bei jedem Start überschrieben |

**SICHERHEITSHINWEIS:** Da dies ein PoC ist, werden sensible Daten (Salts, Tokens) absichtlich geloggt. **IN PRODUKTION NIEMALS TUN!**

### 12.2 Log-Dateien

```
POC/logs/
├── issuer_debug.log    # Issuer-Operationen
├── wallet_debug.log    # Wallet-Operationen
└── verifier_debug.log  # Verifier-Operationen
```

### 12.3 Logger-Modul (logger_config.py)

Das Modul stellt spezialisierte Logger-Klassen bereit:

```python
from logger_config import get_issuer_logger, get_wallet_logger, get_verifier_logger

# Issuer
logger = get_issuer_logger()
logger.log_disclosure_creation("given_name", "Max", salt, disclosure_array)
logger.log_hashing("given_name", disclosure_b64, hash_digest)
logger.log_credential_issued("1234-CODE", status_index=0)

# Wallet
logger = get_wallet_logger()
logger.log_outgoing_request("POST", url, body)
logger.log_disclosure_selection(all_claims, selected_claims)
logger.log_kb_jwt_creation(nonce, audience, sd_hash)

# Verifier
logger = get_verifier_logger()
logger.log_presentation_received(sd_jwt_preview, disclosures_count, has_kb_jwt)
logger.log_hash_verification(claim_name, disclosure, computed_hash, found_in_sd)
logger.log_verification_result(checks, all_passed)
```

### 12.4 Log-Format

```
[2025-11-03 14:32:15] [INFO] [sdjwt.issuer] :: SCHRITT 1 - RAW DATA für Bürger [1234-CODE]
[2025-11-03 14:32:15] [DEBUG] [sdjwt.issuer] :: Geladene Daten:
{
  "given_name": "Max",
  "family_name": "Mustermann",
  "birthdate": "1990-01-15"
}
[2025-11-03 14:32:15] [INFO] [sdjwt.issuer] :: SCHRITT 2 - DISCLOSURE für 'given_name'
[2025-11-03 14:32:15] [DEBUG] [sdjwt.issuer] ::   Claim-Name: given_name
[2025-11-03 14:32:15] [DEBUG] [sdjwt.issuer] ::   Claim-Wert: Max
[2025-11-03 14:32:15] [DEBUG] [sdjwt.issuer] ::   Salt: trMX9skzGJq4Lp...
```

### 12.5 IssuerLogger-Methoden

| Methode | Beschreibung |
|---------|---------------|
| `log_raw_data(citizen_code, data)` | Bürgerdaten aus DB |
| `log_salt_generation(claim_name, salt)` | Salt-Erzeugung |
| `log_disclosure_creation(...)` | Disclosure-Array |
| `log_hashing(claim_name, disclosure_b64, hash)` | SHA-256 Prozess |
| `log_token_structure(payload, count)` | SD-JWT Payload |
| `log_decoy_hashes(count, hashes)` | Decoy-Hashes (v4.0) |
| `log_signature(algorithm, key_id)` | EdDSA Signatur |
| `log_status_list_update(idx, old, new)` | Revocation |
| `log_credential_issued(citizen_code, idx)` | Erfolgreiche Ausstellung |
| `log_offer_created(code, short_code, uri)` | Credential Offer |

### 12.6 WalletLogger-Methoden

| Methode | Beschreibung |
|---------|---------------|
| `log_key_generation(public_key_b64)` | Neue Keys |
| `log_key_loaded(public_key_b64)` | Keys geladen |
| `log_outgoing_request(method, url, body)` | HTTP Request |
| `log_incoming_response(status, body)` | HTTP Response |
| `log_credential_received(issuer, preview, count)` | Credential empfangen |
| `log_credential_stored(id, claims)` | Speicherung |
| `log_disclosure_selection(all, selected)` | Privacy-Entscheidung |
| `log_kb_jwt_creation(nonce, aud, hash)` | Key Binding JWT |
| `log_presentation_sent(url, count)` | Präsentation gesendet |

### 12.7 VerifierLogger-Methoden

| Methode | Beschreibung |
|---------|---------------|
| `log_presentation_received(preview, count, has_kb)` | Empfangene Präsentation |
| `log_signature_verification(issuer, passed, alg)` | Signaturprüfung |
| `log_hash_verification(name, disc, hash, found)` | Hash-Abgleich |
| `log_kb_jwt_verification(passed, nonce, aud)` | KB-JWT Prüfung |
| `log_status_check(uri, idx, bit)` | Revocation-Status |
| `log_verification_result(checks, passed)` | Finale Checkliste |
| `log_extracted_claims(claims)` | Extrahierte Daten |
| `log_nonce_generated(nonce, session_id)` | Challenge erstellt |
| `log_nonce_consumed(nonce)` | Nonce verbraucht |

### 12.8 Kombination mit Live-Inspection (v3.0)

Beide Systeme arbeiten parallel:
- **Live-Inspection (log_manager.py):** Terminal-Visualisierung in Echtzeit
- **Deep-Trace (logger_config.py):** Persistente Datei für spätere Analyse

```python
# Issuer: Beide Systeme nutzen
if CONFIG.get("inspection_mode", False):
    crypto_insight.show_salting(claim_name, value, salt, array)  # Terminal
    
file_logger = get_issuer_logger()
file_logger.log_disclosure_creation(claim_name, value, salt, array)  # Datei
```

---

## 13. Version 6.0: CLI Certificate Renewal

### 13.1 Übersicht

Version 6.0 fügt CLI-Argumente für automatisierte TLS-Zertifikatserneuerung hinzu. Dies ermöglicht Cron-Jobs und CI/CD-Integration.

| Feature | Beschreibung |
|---------|---------------|
| `--renew-certs` | CLI-Flag für Zertifikatserneuerung |
| ACME Support | Let's Encrypt mit Cloudflare DNS-01 |
| Self-Signed Fallback | Wenn ACME nicht konfiguriert |
| Plattformunabhängig | Windows & Linux |

### 13.2 Verwendung

```bash
# Issuer: Nur Zertifikate erneuern (ohne Server zu starten)
python issuer.py --renew-certs

# Verifier: Nur Zertifikate erneuern
python verifier.py --renew-certs
```

### 13.3 Exit-Codes

| Code | Bedeutung |
|------|----------|
| 0 | Zertifikate erfolgreich erneuert |
| 1 | Fehler bei Erneuerung |

### 13.4 Prozessablauf

```
┌─────────────────────────────────────────────────────────────┐
│                   --renew-certs Flow                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Prüfe: ACME-Config vorhanden?                          │
│     └─ certs/acme_config.json                               │
│                                                             │
│  2a. JA: ACME/Let's Encrypt                                 │
│      ├─ Setup Cloudflare DNS                                │
│      ├─ ACME Account registrieren                           │
│      └─ Zertifikat anfordern (DNS-01 Challenge)             │
│                                                             │
│  2b. NEIN: Fallback Self-Signed                             │
│      └─ generate_self_signed_cert()                         │
│                                                             │
│  3. Speichere Zertifikat:                                   │
│     ├─ certs/issuer.crt / certs/verifier.crt               │
│     └─ certs/issuer.key / certs/verifier.key               │
│                                                             │
│  4. Exit mit Code 0 (Erfolg) oder 1 (Fehler)               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 13.5 ACME-Konfiguration

Für Let's Encrypt mit Cloudflare DNS müssen folgende Werte in der Komponenten-Config gesetzt sein:

```json
{
  "ssl": {
    "mode": "acme",
    "acme": {
      "domain": "issuer.example.com",
      "email": "admin@example.com",
      "cloudflare_token": "<API-Token mit Zone:DNS:Edit>",
      "use_staging": true
    }
  }
}
```

**Staging vs. Production:**
- `use_staging: true` → Let's Encrypt Staging (Rate-Limit-frei, nicht vertrauenswürdig)
- `use_staging: false` → Let's Encrypt Production (Rate-Limited, Browser-vertrauenswürdig)

### 13.6 Cron-Job Beispiel

```bash
# Täglich um 3:00 Uhr Zertifikate prüfen/erneuern
0 3 * * * cd /path/to/POC && python issuer.py --renew-certs >> /var/log/cert-renewal.log 2>&1
0 3 * * * cd /path/to/POC && python verifier.py --renew-certs >> /var/log/cert-renewal.log 2>&1
```

### 13.7 cert_manager.py - Hauptfunktionen

```python
# Selbstsigniertes Zertifikat erstellen
from cert_manager import generate_self_signed_cert

success = generate_self_signed_cert(
    domain="localhost",
    cert_path="certs/issuer.crt",
    key_path="certs/issuer.key",
    days_valid=365
)

# ACME/Let's Encrypt
from cert_manager import AcmeCertManager

manager = AcmeCertManager(use_staging=True)
manager.setup_cloudflare(api_token)
manager.register_account(email)
manager.issue_certificate(domain, cert_path, key_path)
```

### 13.8 Argparse-Integration

```python
# issuer.py / verifier.py
import argparse

parser = argparse.ArgumentParser(description="SD-JWT Server")
parser.add_argument(
    '--renew-certs',
    action='store_true',
    help='TLS-Zertifikate erneuern und beenden'
)
args = parser.parse_args()

if args.renew_certs:
    load_config()
    success = renew_certificates()
    sys.exit(0 if success else 1)
```

### 13.9 Fehlerbehandlung

Die `renew_certificates()` Funktion behandelt folgende Szenarien:

| Szenario | Verhalten |
|----------|----------|
| ACME konfiguriert, erfolgreich | Zertifikat erneuert, Exit 0 |
| ACME konfiguriert, fehlgeschlagen | Fallback auf Self-Signed |
| ACME nicht konfiguriert | Self-Signed erstellt, Exit 0 |
| cert_manager nicht importierbar | Fehler, Exit 1 |
| cryptography nicht installiert | Fehler, Exit 1 |

---

## 14. Version 7.0: Usability & Hardening

### 14.1 Übersicht

Version 7.0 konzentriert sich auf Usability-Verbesserungen und die Härtung bestehender Features:

| Feature | Beschreibung |
|---------|--------------|
| Short-Codes erweitert | Von 4-stellig auf 6-stellig (mehr Kollisionsresistenz) |
| Clock Skew reduziert | Von 60s auf 20s (striktere Validierung) |
| Hilfe beim Start | Alle Komponenten zeigen automatisch Hilfe-Befehle |
| Server-Ready-Check | Issuer/Verifier prüfen ob Port erreichbar, bevor CLI startet |

### 14.2 Short-Codes (6-stellig)

Short-Codes wurden von 4 auf 6 Stellen erweitert, um Kollisionen bei höherem Durchsatz zu vermeiden:

```python
# v7.0: 6-stelliger Short-Code
short_code = str(secrets.randbelow(1000000)).zfill(6)
while short_code in short_codes:  # Kollisionen vermeiden
    short_code = str(secrets.randbelow(1000000)).zfill(6)
```

### 14.3 Clock Skew Toleranz (20s)

Die Toleranz für Uhren-Abweichungen wurde von 60 auf 20 Sekunden reduziert:

```python
# sd_jwt_utils.py
CLOCK_SKEW_LEEWAY = 20  # v7.0: striktere Validierung
```

Dies ist ein bewusster Trade-off: Die VMs im PoC-Betrieb sollten hinreichend synchron sein, gleichzeitig wird die Sicherheit durch kürzere Toleranz erhöht.

### 14.4 Automatische Hilfe

Alle drei Komponenten zeigen beim Start automatisch die verfügbaren Befehle an:

```python
# command_loop() in issuer.py, wallet.py, verifier.py
def command_loop():
    show_help()  # v7.0: Hilfe automatisch anzeigen
    while True:
        ...
```

### 14.5 Server-Ready-Check

Issuer und Verifier warten nach dem Flask-Thread-Start aktiv darauf, dass der Port erreichbar ist:

```python
deadline = time.time() + 5.0
while time.time() < deadline:
    try:
        with socket.create_connection((target_host, CONFIG["port"]), timeout=0.5):
            server_ready = True
            break
    except OSError:
        time.sleep(0.1)
```

---

## 15. Weiterführende Dokumentation

Für eine vollständige technische Referenz aller Funktionen, Datenformate und API-Spezifikationen siehe:

→ **[ARCHITEKTUR_TECHNISCH.md](ARCHITEKTUR_TECHNISCH.md)**

Diese Datei enthält:
- Alle Funktionssignaturen mit Parameterbeschreibungen
- Vollständige JSON-Schemas für alle Dateiformate
- Detaillierte API-Request/Response-Beispiele
- Kryptografische Implementierungsdetails
- Replikations-Anleitung für das gesamte System

---

*Dokumentation erstellt für das DHBW-Modul "Neue Konzepte" - Proof of Concept Selective Disclosure*

*Version 6.0 - November 2025*
