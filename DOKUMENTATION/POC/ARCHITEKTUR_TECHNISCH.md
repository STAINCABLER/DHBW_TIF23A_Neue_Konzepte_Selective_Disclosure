# SD-JWT VC PoC - Technische Architektur-Dokumentation

> **Zielgruppe:** Entwickler, die das System verstehen und replizieren möchten  
> **Version:** 6.0  
> **Stand:** November 2025

---

## Inhaltsverzeichnis

1. [Systemübersicht](#1-systemübersicht)
2. [Dateien & Module](#2-dateien--module)
3. [sd_jwt_utils.py - Kryptografie-Bibliothek](#3-sd_jwt_utilspy---kryptografie-bibliothek)
4. [issuer.py - Credential-Aussteller](#4-issuerpy---credential-aussteller)
5. [wallet.py - Digitale Brieftasche](#5-walletpy---digitale-brieftasche)
6. [verifier.py - Credential-Prüfer](#6-verifierpy---credential-prüfer)
7. [config_manager.py - Konfigurationsverwaltung](#7-config_managerpy---konfigurationsverwaltung)
8. [log_manager.py - Live-Inspection (v3.0)](#8-log_managerpy---live-inspection-v30)
9. [logger_config.py - Deep-Trace Logging (v5.0)](#9-logger_configpy---deep-trace-logging-v50)
10. [cert_manager.py - TLS-Zertifikate (v6.0)](#10-cert_managerpy---tls-zertifikate-v60)
11. [Datenformate & Schemas](#11-datenformate--schemas)
12. [API-Spezifikation](#12-api-spezifikation)
13. [Datenflüsse](#13-datenflüsse)
14. [Kryptografische Details](#14-kryptografische-details)
15. [Replikations-Anleitung](#15-replikations-anleitung)

---

## 1. Systemübersicht

### 1.1 Komponenten-Architektur

```
┌────────────────────────────────────────────────────────────────────────┐
│                         SD-JWT VC PROOF OF CONCEPT                     │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐            │
│  │   ISSUER    │      │   WALLET    │      │  VERIFIER   │            │
│  │  Flask:5001 │◄────►│  Terminal   │◄────►│  Flask:5002 │            │
│  └──────┬──────┘      └──────┬──────┘      └──────┬──────┘            │
│         │                    │                    │                    │
│         ▼                    ▼                    ▼                    │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐            │
│  │ citizen_db  │      │wallet_store │      │trust_registry│           │
│  │   .json     │      │   .json     │      │    .json    │            │
│  └─────────────┘      └─────────────┘      └─────────────┘            │
│                                                                        │
├────────────────────────────────────────────────────────────────────────┤
│                      SHARED MODULES                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                 │
│  │sd_jwt_utils  │  │config_manager│  │ log_manager  │                 │
│  └──────────────┘  └──────────────┘  └──────────────┘                 │
│  ┌──────────────┐  ┌──────────────┐                                   │
│  │logger_config │  │ cert_manager │                                   │
│  └──────────────┘  └──────────────┘                                   │
└────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Technologie-Stack

| Komponente | Technologie | Version |
|------------|-------------|---------|
| Sprache | Python | 3.10+ |
| Web-Framework | Flask | ≥2.3.0 |
| HTTP-Client | requests | ≥2.31.0 |
| Kryptografie | cryptography | ≥41.0.0 |
| Terminal-UI | rich | ≥13.0.0 |
| QR-Codes | segno | ≥1.6.0 |
| ACME (optional) | acme, josepy | ≥2.0.0 |

### 1.3 Kryptografische Primitive

| Zweck | Algorithmus | Standard |
|-------|-------------|----------|
| Signaturen | Ed25519 (EdDSA) | RFC 8032 |
| Hashing | SHA-256 | FIPS 180-4 |
| Encoding | Base64 URL-safe | RFC 4648 |
| Token-Format | JWT | RFC 7519 |
| SD-JWT | Selective Disclosure JWT | IETF draft-ietf-oauth-selective-disclosure-jwt |

---

## 2. Dateien & Module

### 2.1 Verzeichnisstruktur

```
POC/
├── sd_jwt_utils.py      # 694 Zeilen - Kryptografie-Kern
├── issuer.py            # 818 Zeilen - Issuer Server
├── wallet.py            # 845 Zeilen - Wallet Client
├── verifier.py          # 877 Zeilen - Verifier Server
├── config_manager.py    # 788 Zeilen - Konfigurationsverwaltung
├── log_manager.py       # 471 Zeilen - Live-Inspection UI
├── logger_config.py     # 352 Zeilen - Deep-Trace File-Logging
├── cert_manager.py      # 676 Zeilen - TLS-Zertifikate
├── requirements.txt     # Abhängigkeiten
│
├── citizen_db.json      # Bürgerdatenbank (Input)
├── issuer_keys.json     # Issuer Ed25519 Keys (generiert)
├── wallet_store.json    # Wallet-Speicher (generiert)
├── trusted_registry.json# Trust Registry für Verifier
│
├── configs/             # Komponenten-Konfigurationen
│   ├── issuer_config.json
│   ├── verifier_config.json
│   └── wallet_config.json
│
├── certs/               # TLS-Zertifikate
│   ├── issuer.crt
│   ├── issuer.key
│   ├── verifier.crt
│   └── verifier.key
│
└── logs/                # Debug-Logdateien (v5.0)
    ├── issuer_debug.log
    ├── wallet_debug.log
    └── verifier_debug.log
```

### 2.2 Modul-Abhängigkeiten

```
                    sd_jwt_utils.py
                          │
         ┌────────────────┼────────────────┐
         │                │                │
         ▼                ▼                ▼
    issuer.py        wallet.py       verifier.py
         │                │                │
         ├───────────┬────┴────┬───────────┤
         │           │         │           │
         ▼           ▼         ▼           ▼
  config_manager  log_manager  logger_config  cert_manager
```

---

## 3. sd_jwt_utils.py - Kryptografie-Bibliothek

### 3.1 Modul-Übersicht

Zentrale Bibliothek für alle kryptografischen Operationen. **694 Zeilen Code**.

### 3.2 Konstanten

```python
CLOCK_SKEW_LEEWAY = 60  # Sekunden Toleranz für Zeitprüfungen (v4.0)
```

### 3.3 Funktionen - Key Management

#### `generate_ed25519_keypair()`
```python
def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """
    Generiert ein neues Ed25519 Schlüsselpaar.
    
    Returns:
        Tuple[bytes, bytes]: (private_key_bytes, public_key_bytes)
        
    Beispiel:
        private, public = generate_ed25519_keypair()
        # private: 32 Bytes (Raw Seed)
        # public: 32 Bytes (Raw Public Key)
    """
```

#### `load_private_key(key_bytes: bytes)`
```python
def load_private_key(key_bytes: bytes) -> Ed25519PrivateKey:
    """
    Konvertiert Raw Bytes zu einem Ed25519PrivateKey Objekt.
    
    Args:
        key_bytes: 32-Byte Private Key Seed
        
    Returns:
        Ed25519PrivateKey: Cryptography-Objekt für Signatur-Operationen
    """
```

#### `load_public_key(key_bytes: bytes)`
```python
def load_public_key(key_bytes: bytes) -> Ed25519PublicKey:
    """
    Konvertiert Raw Bytes zu einem Ed25519PublicKey Objekt.
    
    Args:
        key_bytes: 32-Byte Public Key
        
    Returns:
        Ed25519PublicKey: Cryptography-Objekt für Verifikation
    """
```

#### `key_to_base64(key_bytes: bytes) -> str`
```python
def key_to_base64(key_bytes: bytes) -> str:
    """
    Kodiert Key-Bytes als Base64 URL-safe String (ohne Padding).
    
    Args:
        key_bytes: Raw Key Bytes
        
    Returns:
        str: Base64URL-kodierter String
    """
```

#### `base64_to_key(b64_string: str) -> bytes`
```python
def base64_to_key(b64_string: str) -> bytes:
    """
    Dekodiert Base64 URL-safe String zu Key-Bytes.
    
    Args:
        b64_string: Base64URL-kodierter String
        
    Returns:
        bytes: Raw Key Bytes
    """
```

### 3.4 Funktionen - JWT Encoding/Decoding

#### `base64url_encode(data: bytes) -> str`
```python
def base64url_encode(data: bytes) -> str:
    """
    Base64 URL-safe Encoding ohne Padding.
    
    Args:
        data: Bytes zu enkodieren
        
    Returns:
        str: Base64URL String (RFC 4648 §5)
    """
```

#### `base64url_decode(data: str) -> bytes`
```python
def base64url_decode(data: str) -> bytes:
    """
    Base64 URL-safe Decoding mit automatischem Padding.
    
    Args:
        data: Base64URL String
        
    Returns:
        bytes: Dekodierte Bytes
    """
```

#### `encode_jwt_part(obj: dict) -> str`
```python
def encode_jwt_part(obj: dict) -> str:
    """
    Enkodiert ein Dictionary als JWT-Teil (JSON → UTF-8 → Base64URL).
    
    Args:
        obj: Dictionary (Header oder Payload)
        
    Returns:
        str: Base64URL-kodierter JSON-String
    """
```

#### `decode_jwt_part(part: str) -> dict`
```python
def decode_jwt_part(part: str) -> dict:
    """
    Dekodiert einen JWT-Teil zu einem Dictionary.
    
    Args:
        part: Base64URL-kodierter String
        
    Returns:
        dict: Dekodiertes JSON-Objekt
    """
```

#### `get_jwt_header(jwt: str) -> dict`
```python
def get_jwt_header(jwt: str) -> dict:
    """
    Extrahiert den Header aus einem JWT.
    
    Args:
        jwt: JWT-String (header.payload.signature)
        
    Returns:
        dict: Dekodierter Header
    """
```

#### `get_jwt_payload(jwt: str) -> dict`
```python
def get_jwt_payload(jwt: str) -> dict:
    """
    Extrahiert den Payload aus einem JWT.
    
    Args:
        jwt: JWT-String
        
    Returns:
        dict: Dekodierter Payload
    """
```

### 3.5 Funktionen - Signaturen

#### `create_jwt_header(alg: str = "EdDSA", typ: str = "JWT") -> dict`
```python
def create_jwt_header(alg: str = "EdDSA", typ: str = "JWT") -> dict:
    """
    Erstellt einen Standard-JWT-Header.
    
    Args:
        alg: Signatur-Algorithmus (default: "EdDSA")
        typ: Token-Typ (z.B. "JWT", "sd+jwt", "kb+jwt")
        
    Returns:
        dict: {"alg": "EdDSA", "typ": "..."}
    """
```

#### `sign_jwt(header: dict, payload: dict, private_key: Ed25519PrivateKey) -> str`
```python
def sign_jwt(header: dict, payload: dict, private_key: Ed25519PrivateKey) -> str:
    """
    Signiert Header und Payload zu einem vollständigen JWT.
    
    Args:
        header: JWT-Header Dictionary
        payload: JWT-Payload Dictionary
        private_key: Ed25519 Private Key Objekt
        
    Returns:
        str: Signierter JWT (header.payload.signature)
        
    Prozess:
        1. header_b64 = base64url(json(header))
        2. payload_b64 = base64url(json(payload))
        3. signing_input = header_b64 + "." + payload_b64
        4. signature = ed25519_sign(signing_input, private_key)
        5. signature_b64 = base64url(signature)
        6. return header_b64 + "." + payload_b64 + "." + signature_b64
    """
```

#### `verify_jwt_signature(jwt: str, public_key: Ed25519PublicKey) -> bool`
```python
def verify_jwt_signature(jwt: str, public_key: Ed25519PublicKey) -> bool:
    """
    Verifiziert die Signatur eines JWTs.
    
    Args:
        jwt: JWT-String zu verifizieren
        public_key: Ed25519 Public Key des Signierers
        
    Returns:
        bool: True wenn Signatur gültig, False sonst
        
    Prozess:
        1. Extrahiere header.payload und signature aus JWT
        2. Verifiziere signature über (header + "." + payload)
    """
```

### 3.6 Funktionen - Disclosures

#### `generate_salt(length: int = 16) -> str`
```python
def generate_salt(length: int = 16) -> str:
    """
    Generiert ein kryptografisch sicheres Salt.
    
    Args:
        length: Anzahl Bytes (default: 16)
        
    Returns:
        str: Base64URL-kodiertes Salt
    """
```

#### `create_disclosure(claim_name: str, claim_value: Any, salt: str = None) -> Tuple[str, str]`
```python
def create_disclosure(claim_name: str, claim_value: Any, salt: str = None) -> Tuple[str, str]:
    """
    Erstellt eine Disclosure für einen Claim.
    
    Args:
        claim_name: Name des Claims (z.B. "given_name")
        claim_value: Wert des Claims (z.B. "Max")
        salt: Optional - vordefiniertes Salt (sonst generiert)
        
    Returns:
        Tuple[str, str]: (hash_digest, encoded_disclosure)
            - hash_digest: SHA-256 Hash für _sd Array
            - encoded_disclosure: Base64URL([salt, name, value])
            
    Beispiel:
        hash, disclosure = create_disclosure("given_name", "Max")
        # hash: "WyJ0ck1YS..." (für _sd Array)
        # disclosure: "WyJhYmMiL..." (zur Übertragung)
    """
```

#### `decode_disclosure(disclosure: str) -> Tuple[str, str, Any]`
```python
def decode_disclosure(disclosure: str) -> Tuple[str, str, Any]:
    """
    Dekodiert eine Disclosure.
    
    Args:
        disclosure: Base64URL-kodierte Disclosure
        
    Returns:
        Tuple[str, str, Any]: (salt, claim_name, claim_value)
    """
```

#### `hash_disclosure(disclosure: str) -> str`
```python
def hash_disclosure(disclosure: str) -> str:
    """
    Berechnet den SHA-256 Hash einer Disclosure.
    
    Args:
        disclosure: Base64URL-kodierte Disclosure
        
    Returns:
        str: Base64URL-kodierter SHA-256 Hash
        
    Prozess:
        1. bytes = ascii_encode(disclosure)
        2. hash = sha256(bytes)
        3. return base64url(hash)
    """
```

### 3.7 Funktionen - SD-JWT Erstellung

#### `generate_decoy_hashes(count: int) -> List[str]`
```python
def generate_decoy_hashes(count: int) -> List[str]:
    """
    Generiert Decoy-Hashes für Privacy-Schutz (v4.0).
    
    Decoy-Hashes sind zufällige Hashes, die ins _sd Array gemischt werden,
    um die tatsächliche Anzahl der Claims zu verschleiern.
    
    Args:
        count: Anzahl Decoy-Hashes
        
    Returns:
        List[str]: Liste von Base64URL-kodierten Fake-Hashes
    """
```

#### `create_sd_jwt(...) -> Tuple[str, List[str], Dict[str, str]]`
```python
def create_sd_jwt(
    claims: Dict[str, Any],
    issuer_private_key: Ed25519PrivateKey,
    holder_public_key: bytes,
    issuer: str,
    subject: str,
    status_index: int = None,
    status_uri: str = None,
    add_decoys: bool = False,
    decoy_count: int = 2
) -> Tuple[str, List[str], Dict[str, str]]:
    """
    Erstellt einen vollständigen SD-JWT mit Disclosures.
    
    Args:
        claims: Dictionary mit Claim-Name → Wert
        issuer_private_key: Ed25519 Key zum Signieren
        holder_public_key: Public Key des Holders (für cnf)
        issuer: Issuer URI (für iss claim)
        subject: Subject Identifier (für sub claim)
        status_index: Optional - Index in Status List
        status_uri: Optional - URI der Status List
        add_decoys: Decoy-Hashes hinzufügen? (v4.0)
        decoy_count: Anzahl Decoys
        
    Returns:
        Tuple[str, List[str], Dict[str, str]]:
            - sd_jwt: Signierter SD-JWT String
            - disclosures: Liste aller Disclosures
            - disclosure_map: Claim-Name → Disclosure Mapping
            
    SD-JWT Payload Struktur:
    {
        "iss": "https://issuer.example.com",
        "sub": "citizen:1234",
        "iat": 1699012345,
        "exp": 1730548345,
        "_sd": ["hash1", "hash2", "hash3", ...],
        "_sd_alg": "sha-256",
        "cnf": {
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "holder_public_key_base64"
            }
        },
        "status": {
            "status_list": {
                "idx": 0,
                "uri": "https://issuer.example.com/status"
            }
        }
    }
    """
```

### 3.8 Funktionen - Key Binding JWT

#### `create_kb_jwt(sd_jwt: str, holder_private_key: Ed25519PrivateKey, audience: str, nonce: str) -> str`
```python
def create_kb_jwt(
    sd_jwt: str,
    holder_private_key: Ed25519PrivateKey,
    audience: str,
    nonce: str
) -> str:
    """
    Erstellt ein Key Binding JWT (Holder-Beweis).
    
    Args:
        sd_jwt: Der SD-JWT, an den gebunden wird
        holder_private_key: Private Key des Holders
        audience: Verifier URI
        nonce: Challenge vom Verifier
        
    Returns:
        str: Signierter KB-JWT
        
    KB-JWT Payload:
    {
        "aud": "https://verifier.example.com",
        "nonce": "random_challenge_string",
        "iat": 1699012345,
        "sd_hash": "sha256(sd_jwt)"
    }
    
    Header:
    {
        "alg": "EdDSA",
        "typ": "kb+jwt"
    }
    """
```

#### `verify_kb_jwt(kb_jwt: str, sd_jwt: str, holder_public_key: Ed25519PublicKey, expected_audience: str, expected_nonce: str) -> Tuple[bool, str]`
```python
def verify_kb_jwt(...) -> Tuple[bool, str]:
    """
    Verifiziert ein Key Binding JWT.
    
    Prüft:
        1. Signatur (mit Holder Public Key aus cnf)
        2. sd_hash (muss SHA-256 des SD-JWT sein)
        3. audience (muss Verifier URI sein)
        4. nonce (muss erwarteter Wert sein)
        5. iat (mit CLOCK_SKEW_LEEWAY)
        
    Returns:
        Tuple[bool, str]: (valid, error_message)
    """
```

### 3.9 Funktionen - SD-JWT Validierung

#### `validate_sd_jwt(sd_jwt: str, disclosures: List[str], issuer_public_key: Ed25519PublicKey) -> Tuple[bool, Dict, str]`
```python
def validate_sd_jwt(
    sd_jwt: str,
    disclosures: List[str],
    issuer_public_key: Ed25519PublicKey
) -> Tuple[bool, Dict[str, Any], str]:
    """
    Validiert einen SD-JWT und extrahiert die Claims.
    
    Args:
        sd_jwt: Der SD-JWT String
        disclosures: Liste der Disclosures
        issuer_public_key: Public Key des Issuers
        
    Returns:
        Tuple[bool, Dict, str]: (valid, extracted_claims, error)
        
    Prozess:
        1. Verifiziere Issuer-Signatur
        2. Für jede Disclosure:
           a. Berechne Hash
           b. Prüfe ob Hash in _sd Array
           c. Extrahiere Claim-Name und -Wert
        3. Prüfe Zeitstempel (iat, exp mit CLOCK_SKEW_LEEWAY)
    """
```

#### `extract_holder_public_key(sd_jwt: str) -> bytes`
```python
def extract_holder_public_key(sd_jwt: str) -> bytes:
    """
    Extrahiert den Holder Public Key aus dem cnf Claim.
    
    Args:
        sd_jwt: SD-JWT String
        
    Returns:
        bytes: Raw Public Key Bytes
    """
```

#### `extract_status_info(sd_jwt: str) -> Optional[Tuple[int, str]]`
```python
def extract_status_info(sd_jwt: str) -> Optional[Tuple[int, str]]:
    """
    Extrahiert Status-Informationen aus dem SD-JWT.
    
    Args:
        sd_jwt: SD-JWT String
        
    Returns:
        Optional[Tuple[int, str]]: (status_index, status_uri) oder None
    """
```

### 3.10 Funktionen - Status List (Revocation)

#### `create_status_list(size: int) -> bytes`
```python
def create_status_list(size: int) -> bytes:
    """
    Erstellt eine neue Status List.
    
    Args:
        size: Anzahl der Status-Einträge
        
    Returns:
        bytes: Gzip-komprimierte Bitstring (alle Bits = 0)
        
    Format:
        - 1 Bit pro Status (0 = gültig, 1 = widerrufen)
        - Gzip-komprimiert für Übertragung
    """
```

#### `get_status(status_list: bytes, index: int) -> bool`
```python
def get_status(status_list: bytes, index: int) -> bool:
    """
    Prüft den Status an einem Index.
    
    Args:
        status_list: Gzip-komprimierte Status List
        index: Index des zu prüfenden Credentials
        
    Returns:
        bool: True = widerrufen, False = gültig
    """
```

#### `set_status(status_list: bytes, index: int, revoked: bool) -> bytes`
```python
def set_status(status_list: bytes, index: int, revoked: bool) -> bytes:
    """
    Setzt den Status an einem Index.
    
    Args:
        status_list: Aktuelle Status List
        index: Index des Credentials
        revoked: True = widerrufen, False = gültig
        
    Returns:
        bytes: Aktualisierte Status List
    """
```

#### `status_list_to_base64(status_list: bytes) -> str`
```python
def status_list_to_base64(status_list: bytes) -> str:
    """Konvertiert Status List zu Base64 für Übertragung."""
```

#### `base64_to_status_list(b64: str) -> bytes`
```python
def base64_to_status_list(b64: str) -> bytes:
    """Konvertiert Base64 zurück zu Status List."""
```

### 3.11 Funktionen - Präsentation

#### `create_presentation(sd_jwt: str, disclosures: List[str], kb_jwt: str) -> str`
```python
def create_presentation(
    sd_jwt: str,
    disclosures: List[str],
    kb_jwt: str
) -> str:
    """
    Erstellt einen Präsentations-String.
    
    Args:
        sd_jwt: Der SD-JWT
        disclosures: Ausgewählte Disclosures
        kb_jwt: Key Binding JWT
        
    Returns:
        str: Format "<SD-JWT>~<Disc1>~<Disc2>~...~<KB-JWT>"
        
    Beispiel:
        "eyJhbGc...~WyJhYmMi...~WyJ4eXoi...~eyJhbGc..."
    """
```

#### `parse_presentation(presentation: str) -> Tuple[str, List[str], str]`
```python
def parse_presentation(presentation: str) -> Tuple[str, List[str], str]:
    """
    Parst einen Präsentations-String.
    
    Args:
        presentation: Präsentations-String
        
    Returns:
        Tuple[str, List[str], str]: (sd_jwt, disclosures, kb_jwt)
    """
```

---

## 4. issuer.py - Credential-Aussteller

### 4.1 Modul-Übersicht

Flask-Server für die Credential-Ausstellung. **818 Zeilen Code**.

### 4.2 Globale Variablen

```python
CONFIG: Dict[str, Any] = {}           # Konfiguration
console = Console()                    # Rich Console
app = Flask(__name__)                  # Flask App

# In-Memory Storage
issuer_keys: Dict[str, bytes] = {}     # {"private": bytes, "public": bytes}
citizen_db: Dict[str, Dict] = {}       # Bürgerdatenbank
status_list: bytes = b''               # Revocation Status List
pending_offers: Dict[str, Dict] = {}   # pre_auth_code -> {citizen_code, created_at}
access_tokens: Dict[str, Dict] = {}    # token -> {citizen_code, expires_at}
issued_credentials: Dict[str, int] = {} # citizen_code -> status_index
short_codes: Dict[str, str] = {}       # 4-digit code -> offer_uri (v4.0)
```

### 4.3 Initialisierungs-Funktionen

#### `load_config()`
Lädt oder erstellt die Issuer-Konfiguration via `ComponentConfig("issuer")`.

#### `load_or_create_keys()`
Lädt Keys aus `issuer_keys.json` oder generiert neue Ed25519-Keys.

#### `load_citizen_db()`
Lädt Bürgerdaten aus `citizen_db.json`.

#### `init_status_list()`
Initialisiert die Status List für Revocation.

### 4.4 Flask Endpunkte

| Methode | Endpunkt | Beschreibung |
|---------|----------|--------------|
| GET | `/.well-known/openid-credential-issuer` | Issuer Metadata |
| POST | `/token` | Token-Endpunkt (Pre-Auth Code Flow) |
| POST | `/credential` | Credential-Ausstellung |
| GET | `/status` | Status List abrufen |
| GET | `/health` | Health Check |
| GET | `/shortcode/<code>` | Short-Code Auflösung (v4.0) |

Siehe [API-Spezifikation](#12-api-spezifikation) für Details.

### 4.5 Terminal-Befehle

| Befehl | Beschreibung |
|--------|--------------|
| `offer <code>` | Credential Offer erstellen |
| `list` | Bürger anzeigen |
| `revoke <index>` | Credential widerrufen |
| `status` | Server-Status |
| `help` | Hilfe anzeigen |
| `exit` | Server beenden |

### 4.6 CLI-Argumente (v6.0)

```bash
python issuer.py                # Server normal starten
python issuer.py --renew-certs  # Nur Zertifikate erneuern
```

---

## 5. wallet.py - Digitale Brieftasche

### 5.1 Modul-Übersicht

Terminal-basierte Wallet für Credential-Management. **845 Zeilen Code**.

### 5.2 Globale Variablen

```python
CONFIG: Dict[str, Any] = {}
console = Console()
wallet_data: Dict[str, Any] = {
    "keys": {},         # {"private": str, "public": str}
    "credentials": []   # Liste von Credentials
}
```

### 5.3 Hauptfunktionen

#### `load_wallet()`
Lädt Wallet aus `wallet_store.json`.

#### `save_wallet()`
Speichert Wallet in `wallet_store.json`.

#### `ensure_keys()`
Generiert Ed25519-Keys falls nicht vorhanden.

#### `receive_credential()`
Interaktiver Flow zum Empfangen eines Credentials:
1. Issuer URL eingeben
2. Pre-Auth Code oder Short-Code eingeben
3. Token anfordern (POST `/token`)
4. Proof of Possession erstellen
5. Credential anfordern (POST `/credential`)
6. Credential speichern

#### `present_credential()`
Interaktiver Flow zur Credential-Präsentation:
1. Credential auswählen
2. Verifier eingeben (URL oder Short-Code)
3. Challenge abrufen (GET `/challenge`)
4. Claims auswählen (Selective Disclosure)
5. Consent-Screen anzeigen
6. KB-JWT erstellen
7. Präsentation senden (POST `/verify`)

### 5.4 Terminal-Befehle

| Befehl | Beschreibung |
|--------|--------------|
| `receive` / `r` | Credential empfangen |
| `present` / `p` | Credential präsentieren |
| `list` / `l` | Credentials anzeigen |
| `delete` | Credential löschen |
| `keys` | Keys anzeigen |
| `help` | Hilfe anzeigen |
| `exit` | Wallet beenden |

---

## 6. verifier.py - Credential-Prüfer

### 6.1 Modul-Übersicht

Flask-Server für die Credential-Verifikation. **877 Zeilen Code**.

### 6.2 Globale Variablen

```python
CONFIG: Dict[str, Any] = {}
console = Console()
app = Flask(__name__)

# In-Memory Storage
pending_challenges: Dict[str, Dict] = {}  # nonce -> {created_at, state}
issuer_keys_cache: Dict[str, bytes] = {}  # issuer_uri -> public_key
short_codes: Dict[str, str] = {}          # 4-digit code -> nonce (v4.0)
TRUST_REGISTRY: Dict[str, Any] = {}       # Vertrauenswürdige Issuers
```

### 6.3 Verifikationsprozess

Die `verify_endpoint()` Funktion führt 11 Prüfschritte durch:

1. **Präsentation parsen** - SD-JWT, Disclosures, KB-JWT trennen
2. **Issuer prüfen** - In Trust Registry?
3. **Issuer Key abrufen** - Aus Cache oder via Metadata
4. **Issuer Signatur** - EdDSA Verifikation
5. **Disclosures validieren** - Hash-Abgleich mit _sd Array
6. **Holder Key extrahieren** - Aus cnf Claim
7. **KB-JWT Payload** - Nonce und Audience extrahieren
8. **Nonce prüfen** - In pending_challenges?
9. **KB-JWT Signatur** - Mit Holder Key verifizieren
10. **SD-Hash prüfen** - Binding zwischen KB-JWT und SD-JWT
11. **Revocation prüfen** - Status List abrufen

### 6.4 Flask Endpunkte

| Methode | Endpunkt | Beschreibung |
|---------|----------|--------------|
| GET | `/challenge` | Challenge (Nonce) generieren |
| POST | `/verify` | Präsentation verifizieren |
| GET | `/health` | Health Check |
| GET | `/shortcode/<code>` | Short-Code Auflösung (v4.0) |

### 6.5 Terminal-Befehle

| Befehl | Beschreibung |
|--------|--------------|
| `request` / `r` | Verification Request erstellen |
| `challenges` / `c` | Offene Challenges anzeigen |
| `clear` | Abgelaufene Challenges löschen |
| `status` | Server-Status |
| `help` | Hilfe anzeigen |
| `exit` | Server beenden |

### 6.6 CLI-Argumente (v6.0)

```bash
python verifier.py                # Server normal starten
python verifier.py --renew-certs  # Nur Zertifikate erneuern
```

---

## 7. config_manager.py - Konfigurationsverwaltung

### 7.1 Modul-Übersicht

Zentrale Konfigurationsverwaltung mit First-Run Setup. **788 Zeilen Code**.

### 7.2 Klasse: ComponentConfig

```python
class ComponentConfig:
    """
    Verwaltet die Konfiguration einer Komponente.
    
    Verwendung:
        config = ComponentConfig("issuer")
        CONFIG = config.load_or_setup()
    """
    
    def __init__(self, component: str):
        """
        Args:
            component: "issuer" | "verifier" | "wallet"
        """
    
    def load_or_setup(self) -> Dict[str, Any]:
        """Lädt Config oder startet First-Run Setup."""
    
    def is_first_run(self) -> bool:
        """Prüft ob erster Start."""
    
    def load_config(self) -> Dict[str, Any]:
        """Lädt Config aus JSON-Datei."""
    
    def save_config(self) -> None:
        """Speichert Config in JSON-Datei."""
    
    def run_first_time_setup(self) -> Dict[str, Any]:
        """Interaktiver Setup-Assistent."""
```

### 7.3 Default-Konfigurationen

Siehe [Datenformate & Schemas](#11-datenformate--schemas).

---

## 8. log_manager.py - Live-Inspection (v3.0)

### 8.1 Modul-Übersicht

Terminal-Visualisierung für kryptografische Operationen. **471 Zeilen Code**.

### 8.2 Klasse: CryptoInsight (Issuer)

```python
class CryptoInsight:
    """Visualisiert kryptografische Operationen beim Issuer."""
    
    @staticmethod
    def show_raw_data(citizen_code: str, data: Dict[str, Any]):
        """Zeigt Rohdaten aus der Datenbank."""
    
    @staticmethod
    def show_salting(claim_name: str, claim_value: Any, salt: str, disclosure_array: List):
        """Zeigt den Salting-Prozess."""
    
    @staticmethod
    def show_hashing(claim_name: str, disclosure_b64: str, hash_digest: str):
        """Zeigt den Hashing-Prozess."""
    
    @staticmethod
    def show_token_structure(payload: Dict, disclosures_count: int):
        """Zeigt die finale Token-Struktur."""
    
    @staticmethod
    def show_signature(algorithm: str, key_id: str):
        """Zeigt die Signatur-Operation."""
    
    @staticmethod
    def show_status_list_update(index: int, old_value: int, new_value: int):
        """Zeigt eine Status-List-Änderung."""
```

### 8.3 Klasse: TrafficMonitor (Wallet)

```python
class TrafficMonitor:
    """Visualisiert HTTP-Traffic bei der Wallet."""
    
    @staticmethod
    def show_outgoing_request(method: str, url: str, body: Optional[Dict] = None):
        """Zeigt ausgehenden HTTP-Request."""
    
    @staticmethod
    def show_incoming_response(status_code: int, body: Optional[Dict] = None):
        """Zeigt eingehende HTTP-Response."""
    
    @staticmethod
    def show_credential_storage(credential_summary: Dict):
        """Zeigt Credential-Speicherung."""
    
    @staticmethod
    def show_disclosure_selection(all_claims: List[str], selected_claims: List[str]):
        """Zeigt Privacy-Entscheidung."""
    
    @staticmethod
    def show_kb_jwt_creation(nonce: str, audience: str, sd_hash: str):
        """Zeigt KB-JWT Erstellung."""
    
    @staticmethod
    def show_presentation_packet(sd_jwt: str, disclosure_count: int, kb_jwt: str):
        """Zeigt Präsentations-Paket."""
```

### 8.4 Klasse: VerificationLogic (Verifier)

```python
class VerificationLogic:
    """Visualisiert den Verifikations-Prozess."""
    
    def __init__(self):
        self.checks: List[Dict] = []
    
    def add_check(self, name: str, passed: bool, details: str = ""):
        """Fügt Prüfschritt hinzu."""
    
    def show_incoming_presentation(self, sd_jwt: str, disclosures: List[str], kb_jwt: str):
        """Zeigt empfangene Präsentation."""
    
    def show_hash_verification(self, claim_name: str, disclosure: str, 
                               computed_hash: str, found_in_sd: bool):
        """Zeigt Hash-Verifikation."""
    
    def show_status_check(self, index: int, uri: str, bit_value: int):
        """Zeigt Status-List-Prüfung."""
    
    def show_checklist(self) -> bool:
        """Zeigt finale Checkliste, gibt all_passed zurück."""
    
    def show_extracted_claims(self, claims: Dict[str, Any]):
        """Zeigt extrahierte Claims."""
```

---

## 9. logger_config.py - Deep-Trace Logging (v5.0)

### 9.1 Modul-Übersicht

Dateibasiertes Logging für Debugging. **352 Zeilen Code**.

**WICHTIG:** Da dies ein PoC ist, werden sensible Daten (Salts, Tokens) absichtlich geloggt. **IN PRODUKTION NIEMALS TUN!**

### 9.2 Setup-Funktion

```python
def setup_logger(component_name: str) -> logging.Logger:
    """
    Erstellt einen Logger für eine Komponente.
    
    Args:
        component_name: 'issuer', 'wallet', oder 'verifier'
        
    Returns:
        Logger der in logs/{component}_debug.log schreibt
        
    Die Logdatei wird bei jedem Start ÜBERSCHRIEBEN.
    """
```

### 9.3 Klasse: IssuerLogger

```python
class IssuerLogger:
    def log_raw_data(self, citizen_code: str, data: Dict[str, Any])
    def log_salt_generation(self, claim_name: str, salt: str)
    def log_disclosure_creation(self, claim_name: str, claim_value: Any, 
                                salt: str, disclosure_array: List)
    def log_hashing(self, claim_name: str, disclosure_b64: str, hash_digest: str)
    def log_token_structure(self, payload: Dict, disclosures_count: int)
    def log_decoy_hashes(self, decoy_count: int, decoy_hashes: List[str])
    def log_signature(self, algorithm: str, key_id: str)
    def log_status_list_update(self, index: int, old_value: int, new_value: int)
    def log_credential_issued(self, citizen_code: str, status_index: int)
    def log_offer_created(self, pre_auth_code: str, short_code: str, uri: str)
```

### 9.4 Klasse: WalletLogger

```python
class WalletLogger:
    def log_key_generation(self, public_key_b64: str)
    def log_key_loaded(self, public_key_b64: str)
    def log_outgoing_request(self, method: str, url: str, body: Optional[Dict])
    def log_incoming_response(self, status_code: int, body: Optional[Dict])
    def log_credential_received(self, issuer: str, sd_jwt_preview: str, 
                                 disclosures_count: int)
    def log_credential_stored(self, credential_id: str, claims: List[str])
    def log_presentation_request(self, verifier_url: str, nonce: str, 
                                  requested_claims: List[str])
    def log_disclosure_selection(self, all_claims: List[str], selected_claims: List[str])
    def log_kb_jwt_creation(self, nonce: str, audience: str, sd_hash: str)
    def log_presentation_sent(self, verifier_url: str, disclosure_count: int)
```

### 9.5 Klasse: VerifierLogger

```python
class VerifierLogger:
    def log_presentation_received(self, sd_jwt_preview: str, 
                                    disclosures_count: int, has_kb_jwt: bool)
    def log_signature_verification(self, issuer: str, passed: bool, algorithm: str)
    def log_hash_verification(self, claim_name: str, disclosure: str,
                               computed_hash: str, found_in_sd: bool)
    def log_kb_jwt_verification(self, passed: bool, nonce_match: bool, 
                                  audience_match: bool)
    def log_status_check(self, status_uri: str, index: int, bit_value: int)
    def log_verification_result(self, checks: List[Dict], all_passed: bool)
    def log_extracted_claims(self, claims: Dict[str, Any])
    def log_nonce_generated(self, nonce: str, session_id: str)
    def log_nonce_consumed(self, nonce: str)
```

### 9.6 Singleton-Zugriff

```python
def get_issuer_logger() -> IssuerLogger
def get_wallet_logger() -> WalletLogger
def get_verifier_logger() -> VerifierLogger
```

---

## 10. cert_manager.py - TLS-Zertifikate (v6.0)

### 10.1 Modul-Übersicht

TLS-Zertifikatsverwaltung mit ACME/Let's Encrypt. **676 Zeilen Code**.

### 10.2 Self-Signed Zertifikate

```python
def generate_self_signed_cert(
    domain: str,
    cert_path: str,
    key_path: str,
    days_valid: int = 365
) -> bool:
    """
    Generiert ein selbstsigniertes Zertifikat.
    
    Erstellt:
        - RSA 2048-Bit Private Key
        - X.509 Zertifikat mit SAN für domain, localhost, 127.0.0.1
    """
```

### 10.3 ACME/Let's Encrypt

```python
class AcmeCertManager:
    """
    ACME Certificate Manager mit Cloudflare DNS-01 Challenge.
    
    Verwendung:
        manager = AcmeCertManager(use_staging=True)
        manager.setup_cloudflare(api_token)
        manager.register_account(email)
        manager.issue_certificate(domain, cert_path, key_path)
    """
```

### 10.4 CLI-Verwendung

```bash
python cert_manager.py setup      # Erstmalige Einrichtung
python cert_manager.py issue      # Zertifikate anfordern
python cert_manager.py renew      # Zertifikate erneuern
python cert_manager.py self-sign  # Selbstsignierte Zertifikate
```

---

## 11. Datenformate & Schemas

### 11.1 citizen_db.json - Bürgerdatenbank

```json
{
  "<citizen-code>": {
    "given_name": "string",
    "family_name": "string",
    "birthdate": "YYYY-MM-DD",
    "address": "string",
    "nationality": "ISO 3166-1 alpha-2",
    "document_number": "string"
  }
}
```

**Beispiel:**
```json
{
  "1234-CODE": {
    "given_name": "Max",
    "family_name": "Mustermann",
    "birthdate": "1990-01-15",
    "address": "Musterstraße 42, 12345 Berlin",
    "nationality": "DE",
    "document_number": "T220001234"
  }
}
```

### 11.2 issuer_keys.json - Issuer-Schlüssel

```json
{
  "private": "<base64url-ed25519-private-seed>",
  "public": "<base64url-ed25519-public-key>"
}
```

**Beispiel:**
```json
{
  "private": "l7IxXPJEHKlsqGtYQjqafs_sk8bHAGc_x7u1m6dmdkQ",
  "public": "Djh56m7x1Fhr4lpCp05Xqmempy7mg8f_Tnll4wOfYSY"
}
```

### 11.3 wallet_store.json - Wallet-Speicher

```json
{
  "keys": {
    "private": "<base64url-ed25519-private-seed>",
    "public": "<base64url-ed25519-public-key>"
  },
  "credentials": [
    {
      "id": 1,
      "issuer": "https://issuer.example.com",
      "issued_at": "ISO 8601 datetime",
      "expires_at": "ISO 8601 datetime",
      "sd_jwt": "<sd-jwt-string>",
      "disclosures": ["<disclosure1>", "<disclosure2>", ...],
      "disclosure_mapping": {
        "<claim-name>": "<disclosure>"
      }
    }
  ]
}
```

### 11.4 trusted_registry.json - Trust Registry

```json
{
  "description": "string",
  "version": "string",
  "issuers": {
    "<issuer-uri>": {
      "name": "string",
      "type": "government|commercial|...",
      "public_key": "<base64url-key>|null",
      "fetch_from_metadata": true|false
    }
  },
  "notes": ["string"]
}
```

**Beispiel:**
```json
{
  "description": "Trust Registry - Vertrauenswürdige Issuer",
  "version": "4.0",
  "issuers": {
    "https://issuer.example.com": {
      "name": "Bundesdruckerei Deutschland",
      "type": "government",
      "public_key": null,
      "fetch_from_metadata": true
    }
  }
}
```

### 11.5 Konfigurationsdateien (configs/*.json)

#### issuer_config.json

```json
{
  "issuer_name": "string",
  "issuer_uri": "https://...",
  "host": "0.0.0.0",
  "port": 5001,
  "ssl": {
    "enabled": true|false,
    "cert_file": "path/to/cert.crt",
    "key_file": "path/to/key.key",
    "mode": "self-signed|acme|manual",
    "acme": {
      "domain": "string",
      "email": "string",
      "cloudflare_token": "string",
      "use_staging": true|false
    }
  },
  "status_list_size": 1000,
  "citizen_db_path": "citizen_db.json",
  "keys_path": "issuer_keys.json",
  "inspection_mode": true|false,
  "add_decoys": true|false,
  "decoy_count": 2,
  "first_run_completed": true|false
}
```

#### verifier_config.json

```json
{
  "verifier_name": "string",
  "verifier_uri": "https://...",
  "host": "0.0.0.0",
  "port": 5002,
  "ssl": { /* wie issuer */ },
  "challenge_validity_minutes": 5,
  "trust_registry_file": "trusted_registry.json",
  "clock_skew_seconds": 60,
  "inspection_mode": true|false,
  "trusted_issuers": ["https://...", ...],
  "first_run_completed": true|false
}
```

#### wallet_config.json

```json
{
  "default_issuer": "https://...",
  "default_verifier": "https://...",
  "wallet_store_path": "wallet_store.json",
  "inspection_mode": true|false,
  "first_run_completed": true|false
}
```

---

## 12. API-Spezifikation

### 12.1 Issuer API

#### GET `/.well-known/openid-credential-issuer`

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
      "x": "<base64url-public-key>",
      "use": "sig",
      "kid": "issuer-key-1"
    }]
  },
  "credentials_supported": [{
    "format": "sd_jwt_vc",
    "type": "IdentityCredential",
    "claims": ["given_name", "family_name", "birthdate", "address", "nationality", "document_number"]
  }]
}
```

#### POST `/token`

**Request:**
```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
  "pre-authorized_code": "<code>"
}
```

**Response (200):**
```json
{
  "access_token": "<token>",
  "token_type": "Bearer",
  "expires_in": 600,
  "c_nonce": "<nonce>",
  "c_nonce_expires_in": 300
}
```

**Response (400):**
```json
{
  "error": "unsupported_grant_type|invalid_grant"
}
```

#### POST `/credential`

**Request:**
```http
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "format": "sd_jwt_vc",
  "proof": {
    "proof_type": "jwt",
    "jwt": "<proof-jwt>"
  }
}
```

**Proof JWT Header:**
```json
{
  "alg": "EdDSA",
  "typ": "openid4vci-proof+jwt",
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "<holder-public-key>"
  }
}
```

**Proof JWT Payload:**
```json
{
  "iss": "wallet",
  "aud": "<issuer-uri>",
  "iat": 1699012345,
  "nonce": "<c_nonce>"
}
```

**Response (200):**
```json
{
  "format": "sd_jwt_vc",
  "credential": "<sd-jwt>",
  "disclosures": ["<disc1>", "<disc2>", ...],
  "disclosure_mapping": {
    "given_name": "<disc1>",
    "family_name": "<disc2>",
    ...
  }
}
```

#### GET `/status`

**Response:**
```json
{
  "status_list": "<base64-gzip-compressed-bitstring>",
  "bits": 1,
  "size": 1000
}
```

#### GET `/shortcode/<code>` (v4.0)

**Response (200):**
```json
{
  "found": true,
  "offer_uri": "openid-credential-offer://..."
}
```

**Response (404):**
```json
{
  "found": false,
  "error": "Short-Code XXXX nicht gefunden"
}
```

### 12.2 Verifier API

#### GET `/challenge`

**Response:**
```json
{
  "nonce": "<random-nonce>",
  "state": "<random-state>",
  "audience": "https://verifier.example.com",
  "expires_in": 300
}
```

#### POST `/verify`

**Request:**
```json
{
  "presentation": "<sd-jwt>~<disc1>~<disc2>~<kb-jwt>"
}
```

**Response (200 - Valid):**
```json
{
  "valid": true,
  "issuer": "https://issuer.example.com",
  "claims": {
    "given_name": "Max",
    "family_name": "Mustermann",
    "birthdate": "1990-01-15"
  },
  "holder_verified": true,
  "status": "Credential aktiv (Index 0)"
}
```

**Response (200 - Invalid):**
```json
{
  "valid": false,
  "error": "Invalid issuer signature|Untrusted issuer|..."
}
```

#### GET `/shortcode/<code>` (v4.0)

**Response (200):**
```json
{
  "found": true,
  "nonce": "<nonce>",
  "state": "<state>",
  "verifier_uri": "https://verifier.example.com"
}
```

---

## 13. Datenflüsse

### 13.1 Credential Issuance Flow

```
┌─────────┐                    ┌─────────┐                    ┌─────────┐
│ ISSUER  │                    │ WALLET  │                    │ USER    │
└────┬────┘                    └────┬────┘                    └────┬────┘
     │                              │                              │
     │ offer <citizen-code>        │                              │
     │ ─────────────────────────► QR-Code/Short-Code anzeigen    │
     │                              │                              │
     │                              │ ◄───────────────────────────│
     │                              │   Short-Code eingeben       │
     │                              │                              │
     │ ◄────────────────────────────│                              │
     │   POST /token                │                              │
     │   {pre-authorized_code}      │                              │
     │                              │                              │
     │ ─────────────────────────────►                              │
     │   {access_token, c_nonce}    │                              │
     │                              │                              │
     │ ◄────────────────────────────│                              │
     │   POST /credential           │                              │
     │   {proof_jwt}                │                              │
     │                              │                              │
     │                              │  Erstelle Proof:             │
     │                              │  - Sign(nonce) mit Wallet-Key│
     │                              │                              │
     │ ─────────────────────────────►                              │
     │   {sd_jwt, disclosures}      │                              │
     │                              │                              │
     │                              │  Speichere in wallet_store   │
     │                              │                              │
```

### 13.2 Credential Presentation Flow

```
┌─────────┐                    ┌─────────┐                    ┌──────────┐
│ WALLET  │                    │ VERIFIER│                    │ ISSUER   │
└────┬────┘                    └────┬────┘                    └────┬─────┘
     │                              │                              │
     │ GET /challenge               │                              │
     │ ─────────────────────────────►                              │
     │                              │                              │
     │ ◄─────────────────────────────                              │
     │   {nonce, audience}          │                              │
     │                              │                              │
     │ Wähle Disclosures            │                              │
     │ (User-Interaktion)           │                              │
     │                              │                              │
     │ Erstelle KB-JWT:             │                              │
     │ - sd_hash = SHA256(sd_jwt)   │                              │
     │ - Sign(nonce, aud, sd_hash)  │                              │
     │                              │                              │
     │ POST /verify                 │                              │
     │ {presentation}               │                              │
     │ ─────────────────────────────►                              │
     │                              │                              │
     │                              │  1. Parse Präsentation       │
     │                              │  2. Prüfe Trust Registry     │
     │                              │                              │
     │                              │ GET /.well-known/...         │
     │                              │ ─────────────────────────────►
     │                              │                              │
     │                              │ ◄─────────────────────────────
     │                              │   {jwks: {keys: [...]}}      │
     │                              │                              │
     │                              │  3. Verifiziere Issuer-Sig   │
     │                              │  4. Prüfe Disclosure-Hashes  │
     │                              │  5. Verifiziere KB-JWT       │
     │                              │  6. Prüfe Nonce              │
     │                              │  7. Prüfe SD-Hash            │
     │                              │                              │
     │                              │ GET /status                  │
     │                              │ ─────────────────────────────►
     │                              │                              │
     │                              │ ◄─────────────────────────────
     │                              │   {status_list: "..."}       │
     │                              │                              │
     │                              │  8. Prüfe Revocation-Status  │
     │                              │                              │
     │ ◄─────────────────────────────                              │
     │   {valid: true, claims: {...}}│                              │
     │                              │                              │
```

### 13.3 Präsentations-String Format

```
<SD-JWT>~<Disclosure1>~<Disclosure2>~...~<KB-JWT>

Beispiel:
eyJhbGciOiJFZERTQSIsInR5cCI6InNkK2p3dCJ9.eyJpc3MiOi...~
WyJhYmMxMjMiLCJnaXZlbl9uYW1lIiwiTWF4Il0~
WyJ4eXo0NTYiLCJmYW1pbHlfbmFtZSIsIk11c3Rlcm1hbm4iXQ~
eyJhbGciOiJFZERTQSIsInR5cCI6ImtiK2p3dCJ9.eyJhdWQiOi...

Aufbau:
├── SD-JWT (Header.Payload.Signature)
├── ~ (Separator)
├── Disclosure 1 (Base64URL([salt, "given_name", "Max"]))
├── ~ (Separator)
├── Disclosure 2 (Base64URL([salt, "family_name", "Mustermann"]))
├── ~ (Separator)
└── KB-JWT (Header.Payload.Signature)
```

---

## 14. Kryptografische Details

### 14.1 Ed25519 Schlüssel

| Eigenschaft | Wert |
|-------------|------|
| Algorithmus | EdDSA mit Ed25519 |
| Private Key | 32 Bytes (Seed) |
| Public Key | 32 Bytes |
| Signatur | 64 Bytes |
| Security Level | ~128 Bit |

### 14.2 Disclosure-Erstellung

```
Input:
  claim_name = "given_name"
  claim_value = "Max"
  salt = generate_random_bytes(16)

Prozess:
  1. disclosure_array = [salt, claim_name, claim_value]
     → ["abc123...", "given_name", "Max"]
  
  2. disclosure_json = json.dumps(disclosure_array)
     → '["abc123...", "given_name", "Max"]'
  
  3. disclosure_b64 = base64url(disclosure_json.encode())
     → "WyJhYmMxMjMiLCJnaXZlbl9uYW1lIiwiTWF4Il0"
  
  4. hash = sha256(disclosure_b64.encode('ascii'))
  
  5. hash_b64 = base64url(hash)
     → "tRkMX9skzGJq..." (für _sd Array)

Output:
  hash_digest = "tRkMX9skzGJq..."
  encoded_disclosure = "WyJhYmMxMjMiLCJnaXZlbl9uYW1lIiwiTWF4Il0"
```

### 14.3 SD-JWT Payload Struktur

```json
{
  "iss": "https://issuer.example.com",
  "sub": "citizen:1234-CODE",
  "iat": 1699012345,
  "exp": 1730548345,
  "_sd": [
    "tRkMX9skzGJq...",  // Hash von given_name Disclosure
    "Bp8YqLf2xR...",     // Hash von family_name Disclosure
    "mKp9qLxZr...",      // Hash von birthdate Disclosure
    "xYz123abc..."       // Decoy Hash (v4.0)
  ],
  "_sd_alg": "sha-256",
  "cnf": {
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "TxUj2BDRu3Vpeht5Vs0X6J3w6i3bd5DriYwQyUPLeck"
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

### 14.4 Key Binding JWT Payload

```json
{
  "aud": "https://verifier.example.com",
  "nonce": "random_challenge_from_verifier",
  "iat": 1699012345,
  "sd_hash": "sha256(sd_jwt_string)"
}
```

### 14.5 Status List Format

```
Bitstring Status List (RFC Draft):
- 1 Bit pro Credential
- Bit = 0: Gültig
- Bit = 1: Widerrufen
- Gzip-komprimiert für Übertragung
- Base64URL-kodiert für JSON

Beispiel (1000 Einträge, alle gültig):
  Raw: 125 Bytes Nullen (1000 bits = 125 bytes)
  Gzip: ~20 Bytes
  Base64: ~30 Zeichen
```

---

## 15. Replikations-Anleitung

### 15.1 Voraussetzungen

1. **Python 3.10+** installiert
2. **pip** für Paket-Installation
3. **3 separate Terminals** (oder Maschinen)

### 15.2 Installation

```bash
# Repository klonen
git clone <repository-url>
cd POC

# Virtuelle Umgebung erstellen
python -m venv venv

# Aktivieren (Windows)
.\venv\Scripts\activate

# Aktivieren (Linux/Mac)
source venv/bin/activate

# Abhängigkeiten installieren
pip install -r requirements.txt
```

### 15.3 Zertifikate erstellen (optional)

```bash
# Selbstsignierte Zertifikate für lokale Tests
python cert_manager.py self-sign
```

### 15.4 Komponenten starten

**Terminal 1 - Issuer:**
```bash
python issuer.py
# Erster Start: Interaktiver Setup-Assistent
# Danach: Server auf Port 5001
```

**Terminal 2 - Verifier:**
```bash
python verifier.py
# Erster Start: Interaktiver Setup-Assistent
# Danach: Server auf Port 5002
```

**Terminal 3 - Wallet:**
```bash
python wallet.py
# Erster Start: Interaktiver Setup-Assistent
# Danach: Interaktive Wallet-CLI
```

### 15.5 Demo-Flow ausführen

1. **Issuer:** `offer 1234-CODE`
   → Zeigt QR-Code und Short-Code

2. **Wallet:** `receive`
   → Eingabe: Short-Code (4 Ziffern)
   → Credential wird empfangen und gespeichert

3. **Verifier:** `request`
   → Zeigt QR-Code und Short-Code

4. **Wallet:** `present`
   → Eingabe: Verifier Short-Code
   → Claims auswählen (z.B. nur "given_name")
   → Consent bestätigen
   → Verifikation durchführen

5. **Verifier:** Zeigt Ergebnis und extrahierte Claims

### 15.6 Debugging

- **Logs prüfen:** `logs/issuer_debug.log`, `logs/wallet_debug.log`, `logs/verifier_debug.log`
- **Inspection Mode:** Zeigt kryptografische Details im Terminal
- **Konfiguration anpassen:** `configs/*.json`

---

## Changelog

| Version | Datum | Änderungen |
|---------|-------|------------|
| 1.0 | Nov 2025 | Basis-Implementierung |
| 2.0 | Nov 2025 | Pre-Auth Code Flow, Status List, QR-Codes |
| 3.0 | Nov 2025 | Live-Inspection Mode (log_manager.py) |
| 4.0 | Nov 2025 | Robustheit: Clock Skew, Decoys, Trust Registry, Short-Codes |
| 5.0 | Nov 2025 | Deep-Trace File-Logging (logger_config.py) |
| 6.0 | Nov 2025 | CLI Certificate Renewal (--renew-certs) |

---

*Diese Dokumentation wurde für das DHBW-Projekt "Neue Konzepte: Selective Disclosure" erstellt.*
