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
├── issuer.py            # Issuer Server
├── wallet.py            # Wallet Client  
├── verifier.py          # Verifier Server
├── citizen_db.json      # Simulierte Bürgerdatenbank
├── wallet_store.json    # Wallet-Speicher (generiert)
├── issuer_keys.json     # Issuer-Schlüssel (generiert)
├── requirements.txt     # Python-Abhängigkeiten
└── README.md            # Kurzanleitung
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
2. Issuer-Vertrauenswürdigkeit prüfen
3. Issuer Public Key abrufen
4. SD-JWT Signatur verifizieren
5. Disclosure-Hashes validieren
6. Holder Public Key extrahieren
7. Nonce-Gültigkeit prüfen
8. KB-JWT Signatur verifizieren
9. SD-Hash überprüfen
10. Revocation-Status prüfen

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
  "credential_endpoint": "https://issuer.example.com/credential",
  "token_endpoint": "https://issuer.example.com/token",
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
| 1.0 | 2025-02-06 | Initiale Implementierung |

---

*Dokumentation erstellt für das DHBW-Modul "Neue Konzepte" - Proof of Concept Selective Disclosure*
