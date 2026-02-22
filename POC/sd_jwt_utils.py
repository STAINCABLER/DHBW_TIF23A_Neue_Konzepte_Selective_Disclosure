"""
SD-JWT Utilities - Shared Library für Selective Disclosure JWT
Implementiert gemäß IETF SD-JWT Standard

Funktionen:
- Ed25519 Key-Generierung
- Disclosure-Erstellung und -Hashing
- SD-JWT Erstellung und Validierung
- Status List Management (Revocation)
- Version 4.0: Clock Skew Toleranz, Decoy Hashes
"""

import base64
import hashlib
import json
import secrets
import gzip
import random
from datetime import datetime, timedelta, timezone
from typing import Tuple, List, Dict, Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

# Version 7.0: Clock Skew Toleranz auf 20 Sekunden reduziert
CLOCK_SKEW_LEEWAY = 20


# ============================================================================
# Key Management
# ============================================================================

def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """
    Generiert ein Ed25519 Keypair.
    
    Returns:
        Tuple[bytes, bytes]: (private_key_bytes, public_key_bytes)
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return private_bytes, public_bytes


def load_private_key(private_bytes: bytes) -> Ed25519PrivateKey:
    """Lädt einen Ed25519 Private Key aus Bytes."""
    return Ed25519PrivateKey.from_private_bytes(private_bytes)


def load_public_key(public_bytes: bytes) -> Ed25519PublicKey:
    """Lädt einen Ed25519 Public Key aus Bytes."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    return Ed25519PublicKey.from_public_bytes(public_bytes)


def key_to_base64(key_bytes: bytes) -> str:
    """Konvertiert Key-Bytes zu Base64 URL-safe String."""
    return base64.urlsafe_b64encode(key_bytes).decode('utf-8').rstrip('=')


def base64_to_key(b64_string: str) -> bytes:
    """Konvertiert Base64 URL-safe String zu Key-Bytes."""
    # Padding hinzufügen falls nötig
    padding = 4 - len(b64_string) % 4
    if padding != 4:
        b64_string += '=' * padding
    return base64.urlsafe_b64decode(b64_string)


# ============================================================================
# JWT Encoding/Decoding
# ============================================================================

def base64url_encode(data: bytes) -> str:
    """Base64 URL-safe encoding ohne Padding."""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def base64url_decode(data: str) -> bytes:
    """Base64 URL-safe decoding mit Padding-Korrektur."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def create_jwt_header(alg: str = "EdDSA", typ: str = "JWT") -> Dict[str, str]:
    """Erstellt einen JWT Header."""
    return {"alg": alg, "typ": typ}


def encode_jwt_part(data: Dict) -> str:
    """Encodiert einen JWT-Teil (Header oder Payload) zu Base64."""
    json_bytes = json.dumps(data, separators=(',', ':')).encode('utf-8')
    return base64url_encode(json_bytes)


def decode_jwt_part(encoded: str) -> Dict:
    """Decodiert einen Base64 JWT-Teil zurück zu Dict."""
    json_bytes = base64url_decode(encoded)
    return json.loads(json_bytes.decode('utf-8'))


def sign_jwt(header: Dict, payload: Dict, private_key: Ed25519PrivateKey) -> str:
    """
    Signiert einen JWT mit Ed25519.
    
    Returns:
        str: Kompletter JWT String (header.payload.signature)
    """
    header_b64 = encode_jwt_part(header)
    payload_b64 = encode_jwt_part(payload)
    
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    signature = private_key.sign(signing_input)
    signature_b64 = base64url_encode(signature)
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def verify_jwt_signature(jwt_string: str, public_key: Ed25519PublicKey) -> bool:
    """
    Verifiziert die Signatur eines JWT.
    
    Returns:
        bool: True wenn Signatur gültig, sonst False
    """
    try:
        parts = jwt_string.split('.')
        if len(parts) != 3:
            return False
        
        header_b64, payload_b64, signature_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        signature = base64url_decode(signature_b64)
        
        public_key.verify(signature, signing_input)
        return True
    except Exception:
        return False


def get_jwt_payload(jwt_string: str) -> Dict:
    """Extrahiert den Payload aus einem JWT ohne Signaturprüfung."""
    parts = jwt_string.split('.')
    if len(parts) != 3:
        raise ValueError("Ungültiges JWT Format")
    return decode_jwt_part(parts[1])


def get_jwt_header(jwt_string: str) -> Dict:
    """Extrahiert den Header aus einem JWT."""
    parts = jwt_string.split('.')
    if len(parts) < 1:
        raise ValueError("Ungültiges JWT Format")
    return decode_jwt_part(parts[0])


# ============================================================================
# Disclosure Management
# ============================================================================

def generate_salt(length: int = 16) -> str:
    """Generiert einen zufälligen Salt für Disclosures."""
    return secrets.token_urlsafe(length)


def create_disclosure(claim_name: str, claim_value: Any, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Erstellt eine Disclosure für einen Claim.
    
    Args:
        claim_name: Name des Claims (z.B. "given_name")
        claim_value: Wert des Claims (z.B. "Max")
        salt: Optional, sonst wird einer generiert
    
    Returns:
        Tuple[str, str]: (disclosure_hash, encoded_disclosure)
            - disclosure_hash: SHA-256 Hash für das _sd Array
            - encoded_disclosure: Base64-encodierte Disclosure
    """
    if salt is None:
        salt = generate_salt()
    
    # Disclosure Array: [salt, claim_name, claim_value]
    disclosure_array = [salt, claim_name, claim_value]
    disclosure_json = json.dumps(disclosure_array, separators=(',', ':')).encode('utf-8')
    encoded_disclosure = base64url_encode(disclosure_json)
    
    # SHA-256 Hash der encodierten Disclosure
    hash_bytes = hashlib.sha256(encoded_disclosure.encode('ascii')).digest()
    disclosure_hash = base64url_encode(hash_bytes)
    
    return disclosure_hash, encoded_disclosure


def decode_disclosure(encoded_disclosure: str) -> Tuple[str, str, Any]:
    """
    Decodiert eine Disclosure.
    
    Returns:
        Tuple[str, str, Any]: (salt, claim_name, claim_value)
    """
    disclosure_json = base64url_decode(encoded_disclosure)
    disclosure_array = json.loads(disclosure_json.decode('utf-8'))
    
    if len(disclosure_array) != 3:
        raise ValueError("Ungültiges Disclosure Format")
    
    return disclosure_array[0], disclosure_array[1], disclosure_array[2]


def hash_disclosure(encoded_disclosure: str) -> str:
    """Berechnet den SHA-256 Hash einer encodierten Disclosure."""
    hash_bytes = hashlib.sha256(encoded_disclosure.encode('ascii')).digest()
    return base64url_encode(hash_bytes)


# ============================================================================
# Version 4.0: Clock Skew & Decoy Hashes
# ============================================================================

def validate_time_claims(payload: Dict[str, Any], leeway: int = CLOCK_SKEW_LEEWAY) -> Tuple[bool, str]:
    """
    Validiert die Zeit-Claims (nbf, exp, iat) eines JWT mit Toleranz.
    
    Args:
        payload: JWT Payload mit Zeit-Claims
        leeway: Toleranzbereich in Sekunden (Default: 60)
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    now = datetime.now(timezone.utc)
    now_ts = int(now.timestamp())
    
    # Prüfe "not before" (nbf)
    nbf = payload.get("nbf")
    if nbf is not None:
        if now_ts < (nbf - leeway):
            return False, f"Token noch nicht gültig (nbf: {nbf}, now: {now_ts}, leeway: {leeway}s)"
    
    # Prüfe "expiration" (exp)
    exp = payload.get("exp")
    if exp is not None:
        if now_ts > (exp + leeway):
            return False, f"Token abgelaufen (exp: {exp}, now: {now_ts}, leeway: {leeway}s)"
    
    # Prüfe "issued at" (iat) - sollte nicht in der Zukunft liegen
    iat = payload.get("iat")
    if iat is not None:
        if now_ts < (iat - leeway):
            return False, f"Token aus der Zukunft (iat: {iat}, now: {now_ts})"
    
    return True, ""


def generate_decoy_hashes(count: int = 2) -> List[str]:
    """
    Generiert zufällige Decoy-Hashes für Privacy-Schutz.
    
    Decoy-Hashes sind Fake-Hashes ohne zugehörige Disclosure.
    Sie verschleiern die echte Anzahl der Claims (Anti-Profiling).
    
    Args:
        count: Anzahl der Decoy-Hashes (Default: 2)
    
    Returns:
        List[str]: Liste von Base64URL-codierten Fake-Hashes
    """
    decoys = []
    for _ in range(count):
        # Generiere zufälligen "Salt" und "Fake-Claim"
        fake_salt = generate_salt()
        fake_array = [fake_salt, f"_decoy_{secrets.token_hex(4)}", secrets.token_hex(8)]
        fake_json = json.dumps(fake_array, separators=(',', ':')).encode('utf-8')
        fake_encoded = base64url_encode(fake_json)
        
        # Hash berechnen (wie bei echten Disclosures)
        hash_bytes = hashlib.sha256(fake_encoded.encode('ascii')).digest()
        decoy_hash = base64url_encode(hash_bytes)
        decoys.append(decoy_hash)
    
    return decoys


# ============================================================================
# SD-JWT Creation
# ============================================================================

def create_sd_jwt(
    claims: Dict[str, Any],
    issuer_private_key: Ed25519PrivateKey,
    holder_public_key: bytes,
    issuer: str,
    subject: str,
    status_index: Optional[int] = None,
    status_uri: Optional[str] = None,
    validity_days: int = 365,
    add_decoys: bool = False,
    decoy_count: int = 2
) -> Tuple[str, List[str], Dict[str, str]]:
    """
    Erstellt einen SD-JWT mit selektiv offenbaren Claims.
    
    Args:
        claims: Dict mit Claim-Namen und -Werten
        issuer_private_key: Private Key des Issuers
        holder_public_key: Public Key des Holders (für cnf)
        issuer: Issuer URI
        subject: Subject ID
        status_index: Optional, Index in der Status List
        status_uri: Optional, URI zur Status List
        validity_days: Gültigkeitsdauer in Tagen
        add_decoys: Version 4.0 - Decoy-Hashes hinzufügen (Anti-Profiling)
        decoy_count: Anzahl der Decoy-Hashes (Default: 2)
    
    Returns:
        Tuple[str, List[str], Dict[str, str]]:
            - sd_jwt: Der signierte SD-JWT
            - disclosures: Liste der encodierten Disclosures
            - disclosure_map: Mapping von Claim-Namen zu Disclosures
    """
    sd_array = []
    disclosures = []
    disclosure_map = {}
    
    # Erstelle Disclosures für jeden Claim
    for claim_name, claim_value in claims.items():
        digest, encoded_disclosure = create_disclosure(claim_name, claim_value)
        sd_array.append(digest)
        disclosures.append(encoded_disclosure)
        disclosure_map[claim_name] = encoded_disclosure
    
    # Version 4.0: Decoy-Hashes hinzufügen (Anti-Profiling)
    if add_decoys and decoy_count > 0:
        decoy_hashes = generate_decoy_hashes(decoy_count)
        sd_array.extend(decoy_hashes)
        # Mische Array um Decoys nicht erkennbar zu machen
        random.shuffle(sd_array)
    
    # Erstelle SD-JWT Payload
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=validity_days)
    
    payload = {
        "iss": issuer,
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "_sd": sd_array,
        "_sd_alg": "sha-256",
        "cnf": {
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": key_to_base64(holder_public_key)
            }
        }
    }
    
    # Optional: Status (für Revocation)
    if status_index is not None and status_uri is not None:
        payload["status"] = {
            "status_list": {
                "idx": status_index,
                "uri": status_uri
            }
        }
    
    # Signiere SD-JWT
    header = create_jwt_header(typ="sd+jwt")
    sd_jwt = sign_jwt(header, payload, issuer_private_key)
    
    return sd_jwt, disclosures, disclosure_map


# ============================================================================
# Key Binding JWT
# ============================================================================

def create_kb_jwt(
    sd_jwt: str,
    holder_private_key: Ed25519PrivateKey,
    audience: str,
    nonce: str
) -> str:
    """
    Erstellt einen Key Binding JWT.
    
    Der KB-JWT beweist, dass der Holder den Private Key zum cnf-Claim besitzt.
    
    Args:
        sd_jwt: Der SD-JWT (wird gehasht in sd_hash)
        holder_private_key: Private Key des Holders
        audience: Verifier URI (aud Claim)
        nonce: Challenge Nonce vom Verifier
    
    Returns:
        str: Signierter KB-JWT
    """
    # Hash des SD-JWT für sd_hash Claim
    sd_jwt_hash = hashlib.sha256(sd_jwt.encode('ascii')).digest()
    
    payload = {
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "aud": audience,
        "nonce": nonce,
        "sd_hash": base64url_encode(sd_jwt_hash)
    }
    
    header = create_jwt_header(typ="kb+jwt")
    kb_jwt = sign_jwt(header, payload, holder_private_key)
    
    return kb_jwt


def verify_kb_jwt(
    kb_jwt: str,
    sd_jwt: str,
    holder_public_key: Ed25519PublicKey,
    expected_audience: str,
    expected_nonce: str
) -> bool:
    """
    Verifiziert einen Key Binding JWT.
    
    Prüft:
    - Signatur mit Holder Public Key
    - audience Claim
    - nonce Claim
    - sd_hash Claim
    
    Returns:
        bool: True wenn alle Prüfungen erfolgreich
    """
    try:
        # Signaturprüfung
        if not verify_jwt_signature(kb_jwt, holder_public_key):
            return False
        
        payload = get_jwt_payload(kb_jwt)
        
        # Audience prüfen
        if payload.get("aud") != expected_audience:
            return False
        
        # Nonce prüfen
        if payload.get("nonce") != expected_nonce:
            return False
        
        # SD-Hash prüfen
        expected_hash = base64url_encode(hashlib.sha256(sd_jwt.encode('ascii')).digest())
        if payload.get("sd_hash") != expected_hash:
            return False
        
        return True
    except Exception:
        return False


# ============================================================================
# SD-JWT Validation
# ============================================================================

def validate_sd_jwt(
    sd_jwt: str,
    disclosures: List[str],
    issuer_public_key: Ed25519PublicKey,
    check_time_claims: bool = True
) -> Tuple[bool, Dict[str, Any], str]:
    """
    Validiert einen SD-JWT und extrahiert die offenbarten Claims.
    
    Prüft:
    - Issuer Signatur
    - Zeit-Claims (nbf, exp) mit Clock Skew Toleranz (v4.0)
    - Disclosure Hashes matching
    
    Returns:
        Tuple[bool, Dict[str, Any], str]:
            - valid: True wenn valide
            - claims: Dict mit extrahierten Claims
            - error: Fehlermeldung falls nicht valide
    """
    try:
        # Signaturprüfung
        if not verify_jwt_signature(sd_jwt, issuer_public_key):
            return False, {}, "Issuer Signatur ungültig"
        
        payload = get_jwt_payload(sd_jwt)
        
        # Version 4.0: Zeit-Claims prüfen mit Leeway
        if check_time_claims:
            time_valid, time_error = validate_time_claims(payload)
            if not time_valid:
                return False, {}, time_error
        
        sd_array = payload.get("_sd", [])
        
        # Prüfe ob alle Disclosure-Hashes im _sd Array sind
        # (Decoy-Hashes werden ignoriert - sie haben keine zugehörige Disclosure)
        extracted_claims = {}
        for disclosure in disclosures:
            disclosure_hash = hash_disclosure(disclosure)
            
            if disclosure_hash not in sd_array:
                return False, {}, f"Disclosure Hash nicht gefunden: {disclosure_hash[:20]}..."
            
            # Decode disclosure und extrahiere Claim
            salt, claim_name, claim_value = decode_disclosure(disclosure)
            extracted_claims[claim_name] = claim_value
        
        return True, extracted_claims, ""
    except Exception as e:
        return False, {}, f"Validierungsfehler: {str(e)}"


def extract_holder_public_key(sd_jwt: str) -> bytes:
    """Extrahiert den Holder Public Key aus dem cnf Claim des SD-JWT."""
    payload = get_jwt_payload(sd_jwt)
    cnf = payload.get("cnf", {})
    jwk = cnf.get("jwk", {})
    x = jwk.get("x", "")
    return base64_to_key(x)


def extract_status_info(sd_jwt: str) -> Optional[Tuple[int, str]]:
    """
    Extrahiert Status-Informationen aus dem SD-JWT.
    
    Returns:
        Optional[Tuple[int, str]]: (index, uri) oder None
    """
    payload = get_jwt_payload(sd_jwt)
    status = payload.get("status", {})
    status_list = status.get("status_list", {})
    
    idx = status_list.get("idx")
    uri = status_list.get("uri")
    
    if idx is not None and uri is not None:
        return idx, uri
    return None


# ============================================================================
# Status List (Revocation)
# ============================================================================

def create_status_list(size: int = 1000) -> bytes:
    """
    Erstellt eine neue Bitstring Status List.
    Alle Bits sind initial 0 (gültig).
    
    Returns:
        bytes: Komprimierte Status List
    """
    # Bytes für die Anzahl der Bits
    byte_size = (size + 7) // 8
    bitstring = bytearray(byte_size)
    
    # Komprimieren mit gzip
    compressed = gzip.compress(bytes(bitstring))
    return compressed


def get_status(compressed_list: bytes, index: int) -> bool:
    """
    Prüft den Status an einem bestimmten Index.
    
    Returns:
        bool: True = widerrufen, False = gültig
    """
    # Dekomprimieren
    bitstring = bytearray(gzip.decompress(compressed_list))
    
    byte_index = index // 8
    bit_index = index % 8
    
    if byte_index >= len(bitstring):
        raise IndexError(f"Index {index} außerhalb der Status List")
    
    return bool((bitstring[byte_index] >> (7 - bit_index)) & 1)


def set_status(compressed_list: bytes, index: int, revoked: bool = True) -> bytes:
    """
    Setzt den Status an einem bestimmten Index.
    
    Args:
        compressed_list: Komprimierte Status List
        index: Index des zu ändernden Bits
        revoked: True = widerrufen, False = gültig
    
    Returns:
        bytes: Neue komprimierte Status List
    """
    # Dekomprimieren
    bitstring = bytearray(gzip.decompress(compressed_list))
    
    byte_index = index // 8
    bit_index = index % 8
    
    if byte_index >= len(bitstring):
        raise IndexError(f"Index {index} außerhalb der Status List")
    
    if revoked:
        # Bit auf 1 setzen
        bitstring[byte_index] |= (1 << (7 - bit_index))
    else:
        # Bit auf 0 setzen
        bitstring[byte_index] &= ~(1 << (7 - bit_index))
    
    # Neu komprimieren
    return gzip.compress(bytes(bitstring))


def status_list_to_base64(compressed_list: bytes) -> str:
    """Konvertiert Status List zu Base64 für Transport."""
    return base64url_encode(compressed_list)


def base64_to_status_list(b64_string: str) -> bytes:
    """Konvertiert Base64 zurück zu Status List."""
    return base64url_decode(b64_string)


# ============================================================================
# Presentation Format
# ============================================================================

def create_presentation(sd_jwt: str, disclosures: List[str], kb_jwt: str) -> str:
    """
    Erstellt eine SD-JWT Presentation im Standardformat.
    Format: <SD-JWT>~<Disclosure1>~<Disclosure2>~...~<KB-JWT>
    
    Returns:
        str: Presentation String
    """
    parts = [sd_jwt] + disclosures + [kb_jwt]
    return "~".join(parts)


def parse_presentation(presentation: str) -> Tuple[str, List[str], str]:
    """
    Parst eine SD-JWT Presentation.
    
    Returns:
        Tuple[str, List[str], str]: (sd_jwt, disclosures, kb_jwt)
    """
    parts = presentation.split("~")
    
    if len(parts) < 2:
        raise ValueError("Ungültiges Presentation Format")
    
    sd_jwt = parts[0]
    kb_jwt = parts[-1]
    disclosures = parts[1:-1]
    
    return sd_jwt, disclosures, kb_jwt


if __name__ == "__main__":
    # Schneller Test
    print("SD-JWT Utils - Test")
    
    # Key Generation
    priv, pub = generate_ed25519_keypair()
    print(f"Private Key: {key_to_base64(priv)[:20]}...")
    print(f"Public Key: {key_to_base64(pub)[:20]}...")
    
    # Disclosure Test
    digest, disclosure = create_disclosure("given_name", "Max")
    print(f"Disclosure: {disclosure[:30]}...")
    print(f"Digest: {digest[:20]}...")
    
    salt, name, value = decode_disclosure(disclosure)
    print(f"Decoded: {name} = {value}")
    
    print("\nAlle Tests erfolgreich!")
