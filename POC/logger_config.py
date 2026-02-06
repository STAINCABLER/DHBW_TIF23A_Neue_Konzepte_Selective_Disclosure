"""
Logger Config - Zentrales Deep-Trace Logging-Modul für SD-JWT PoC
Version 5.0: Dateibasiertes Logging für Debugging und Präsentationen

Dieses Modul erstellt persistente Logdateien im /logs Ordner.
Jede Komponente schreibt in ihre eigene Datei:
- issuer_debug.log
- wallet_debug.log
- verifier_debug.log

HINWEIS: Da dies ein PoC ist, werden sensible Daten (Salts, Private Keys, Tokens)
absichtlich in die Logdatei geschrieben, um den kryptografischen Prozess
nachvollziehbar zu machen. IN PRODUKTION NIEMALS TUN!
"""

import os
import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

# ============================================================================
# Konfiguration
# ============================================================================

LOGS_DIR = Path(__file__).parent / "logs"

# Stellt sicher, dass der logs-Ordner existiert
LOGS_DIR.mkdir(exist_ok=True)


# ============================================================================
# Logger-Setup
# ============================================================================

def setup_logger(component_name: str) -> logging.Logger:
    """
    Erstellt einen Logger für eine Komponente.
    
    Args:
        component_name: 'issuer', 'wallet', oder 'verifier'
        
    Returns:
        Konfigurierter Logger der in Datei schreibt
        
    Die Logdatei wird bei jedem Start ÜBERSCHRIEBEN (mode='w'),
    damit nur der letzte Lauf enthalten ist.
    """
    log_file = LOGS_DIR / f"{component_name}_debug.log"
    
    # Erstelle Logger
    logger = logging.getLogger(f"sdjwt.{component_name}")
    logger.setLevel(logging.DEBUG)
    
    # Entferne alte Handler (wichtig bei Mehrfach-Aufrufen)
    logger.handlers = []
    
    # File Handler mit Überschreiben
    file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    
    # Formatter
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(name)s] :: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    
    # Initiale Nachricht
    logger.info("=" * 70)
    logger.info(f"SD-JWT PoC - {component_name.upper()} Debug Log")
    logger.info(f"Session gestartet: {datetime.now().isoformat()}")
    logger.info("=" * 70)
    logger.warning("ACHTUNG: Diese Logdatei enthält sensible Daten für Debug-Zwecke!")
    logger.warning("In Produktion niemals Salts, Private Keys oder Tokens loggen!")
    logger.info("-" * 70)
    
    return logger


def format_json(obj: Any, indent: int = 2) -> str:
    """Formatiert ein Objekt als lesbare JSON-Zeichenkette."""
    try:
        return json.dumps(obj, indent=indent, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(obj)


# ============================================================================
# Issuer-spezifische Logging-Funktionen
# ============================================================================

class IssuerLogger:
    """Spezialisierter Logger für Issuer-Operationen."""
    
    def __init__(self):
        self.logger = setup_logger("issuer")
    
    def log_raw_data(self, citizen_code: str, data: Dict[str, Any]):
        """Loggt die Rohdaten aus der Datenbank."""
        self.logger.info(f"SCHRITT 1 - RAW DATA für Bürger [{citizen_code}]")
        self.logger.debug(f"Geladene Daten:\n{format_json(data)}")
    
    def log_salt_generation(self, claim_name: str, salt: str):
        """Loggt die Salt-Generierung."""
        self.logger.debug(f"Salt generiert für '{claim_name}': {salt}")
    
    def log_disclosure_creation(self, claim_name: str, claim_value: Any, 
                                salt: str, disclosure_array: List):
        """Loggt die Disclosure-Erstellung."""
        self.logger.info(f"SCHRITT 2 - DISCLOSURE für '{claim_name}'")
        self.logger.debug(f"  Claim-Name: {claim_name}")
        self.logger.debug(f"  Claim-Wert: {claim_value}")
        self.logger.debug(f"  Salt: {salt}")
        self.logger.debug(f"  Raw Disclosure: {disclosure_array}")
    
    def log_hashing(self, claim_name: str, disclosure_b64: str, hash_digest: str):
        """Loggt den Hashing-Prozess."""
        self.logger.info(f"SCHRITT 3 - HASHING für '{claim_name}'")
        self.logger.debug(f"  Disclosure (Base64): {disclosure_b64}")
        self.logger.debug(f"  Hash (SHA-256 → Base64URL): {hash_digest}")
    
    def log_token_structure(self, payload: Dict, disclosures_count: int):
        """Loggt die finale Token-Struktur."""
        self.logger.info(f"SCHRITT 4 - TOKEN-BAU ({disclosures_count} Disclosures)")
        self.logger.debug(f"SD-JWT Payload:\n{format_json(payload)}")
    
    def log_decoy_hashes(self, decoy_count: int, decoy_hashes: List[str]):
        """Loggt die generierten Decoy-Hashes."""
        self.logger.info(f"PRIVACY: {decoy_count} Decoy-Hashes hinzugefügt")
        for i, h in enumerate(decoy_hashes):
            self.logger.debug(f"  Decoy {i+1}: {h}")
    
    def log_signature(self, algorithm: str, key_id: str):
        """Loggt die Signatur-Operation."""
        self.logger.info("SCHRITT 5 - SIGNATUR")
        self.logger.debug(f"  Algorithmus: {algorithm}")
        self.logger.debug(f"  Key-ID (gekürzt): {key_id[:50]}...")
        self.logger.info("  ✓ Signatur erfolgreich erstellt")
    
    def log_status_list_update(self, index: int, old_value: int, new_value: int):
        """Loggt eine Status-List-Änderung."""
        status_old = "GÜLTIG" if old_value == 0 else "WIDERRUFEN"
        status_new = "GÜLTIG" if new_value == 0 else "WIDERRUFEN"
        self.logger.warning(f"STATUS LIST UPDATE: Index {index}")
        self.logger.warning(f"  {status_old} (Bit={old_value}) → {status_new} (Bit={new_value})")
    
    def log_credential_issued(self, citizen_code: str, status_index: int):
        """Loggt die erfolgreiche Ausstellung."""
        self.logger.info(f"✓ CREDENTIAL AUSGESTELLT für [{citizen_code}]")
        self.logger.info(f"  Status-Index: {status_index}")
    
    def log_offer_created(self, pre_auth_code: str, short_code: str, uri: str):
        """Loggt ein erstelltes Credential Offer."""
        self.logger.info("CREDENTIAL OFFER ERSTELLT")
        self.logger.debug(f"  Pre-Auth-Code: {pre_auth_code}")
        self.logger.debug(f"  Short-Code: {short_code}")
        self.logger.debug(f"  URI: {uri}")


# ============================================================================
# Wallet-spezifische Logging-Funktionen
# ============================================================================

class WalletLogger:
    """Spezialisierter Logger für Wallet-Operationen."""
    
    def __init__(self):
        self.logger = setup_logger("wallet")
    
    def log_key_generation(self, public_key_b64: str):
        """Loggt die Schlüsselgenerierung."""
        self.logger.info("ED25519 KEYPAIR GENERIERT")
        self.logger.debug(f"  Public Key (Base64): {public_key_b64}")
        self.logger.warning("  Private Key wird NICHT geloggt (auch nicht im PoC)")
    
    def log_key_loaded(self, public_key_b64: str):
        """Loggt das Laden existierender Schlüssel."""
        self.logger.info("KEYPAIR GELADEN")
        self.logger.debug(f"  Public Key (Base64): {public_key_b64}")
    
    def log_outgoing_request(self, method: str, url: str, body: Optional[Dict] = None):
        """Loggt einen ausgehenden HTTP-Request."""
        self.logger.info(f"→ OUTGOING REQUEST: {method} {url}")
        if body:
            self.logger.debug(f"  Request Body:\n{format_json(body)}")
    
    def log_incoming_response(self, status_code: int, body: Optional[Dict] = None):
        """Loggt eine eingehende HTTP-Response."""
        self.logger.info(f"← INCOMING RESPONSE: Status {status_code}")
        if body:
            self.logger.debug(f"  Response Body:\n{format_json(body)}")
    
    def log_credential_received(self, issuer: str, sd_jwt_preview: str, 
                                 disclosures_count: int):
        """Loggt den Empfang eines Credentials."""
        self.logger.info("CREDENTIAL EMPFANGEN (OID4VCI)")
        self.logger.debug(f"  Issuer: {issuer}")
        self.logger.debug(f"  SD-JWT (gekürzt): {sd_jwt_preview[:80]}...")
        self.logger.debug(f"  Anzahl Disclosures: {disclosures_count}")
    
    def log_credential_stored(self, credential_id: str, claims: List[str]):
        """Loggt die Speicherung in wallet_store.json."""
        self.logger.info(f"CREDENTIAL GESPEICHERT: {credential_id}")
        self.logger.debug(f"  Verfügbare Claims: {claims}")
    
    def log_presentation_request(self, verifier_url: str, nonce: str, 
                                  requested_claims: List[str]):
        """Loggt eine empfangene Presentation-Anfrage."""
        self.logger.info("PRESENTATION REQUEST EMPFANGEN (OID4VP)")
        self.logger.debug(f"  Verifier: {verifier_url}")
        self.logger.debug(f"  Nonce: {nonce}")
        self.logger.debug(f"  Angeforderte Claims: {requested_claims}")
    
    def log_disclosure_selection(self, all_claims: List[str], selected_claims: List[str]):
        """Loggt die Auswahl der Disclosures durch den User."""
        self.logger.info("DISCLOSURE SELECTION (Privacy-Entscheidung)")
        for claim in all_claims:
            status = "GESENDET" if claim in selected_claims else "ZURÜCKGEHALTEN"
            self.logger.debug(f"  {claim}: {status}")
    
    def log_kb_jwt_creation(self, nonce: str, audience: str, sd_hash: str):
        """Loggt die Key-Binding JWT Erstellung."""
        self.logger.info("KEY BINDING JWT ERSTELLT")
        self.logger.debug(f"  Nonce: {nonce}")
        self.logger.debug(f"  Audience: {audience}")
        self.logger.debug(f"  SD-JWT Hash: {sd_hash}")
        self.logger.debug("  ✓ Signiert mit Wallet Private Key")
    
    def log_presentation_sent(self, verifier_url: str, disclosure_count: int):
        """Loggt die gesendete Präsentation."""
        self.logger.info(f"PRESENTATION GESENDET an {verifier_url}")
        self.logger.debug(f"  Enthält {disclosure_count} Disclosure(s)")


# ============================================================================
# Verifier-spezifische Logging-Funktionen
# ============================================================================

class VerifierLogger:
    """Spezialisierter Logger für Verifier-Operationen."""
    
    def __init__(self):
        self.logger = setup_logger("verifier")
    
    def log_presentation_received(self, sd_jwt_preview: str, 
                                    disclosures_count: int, has_kb_jwt: bool):
        """Loggt eine empfangene Präsentation."""
        self.logger.info("PRESENTATION EMPFANGEN")
        self.logger.debug(f"  SD-JWT (gekürzt): {sd_jwt_preview[:80]}...")
        self.logger.debug(f"  Anzahl Disclosures: {disclosures_count}")
        self.logger.debug(f"  Key Binding JWT: {'Ja' if has_kb_jwt else 'Nein'}")
    
    def log_signature_verification(self, issuer: str, passed: bool, algorithm: str):
        """Loggt die Signaturprüfung."""
        status = "✓ PASS" if passed else "✗ FAIL"
        self.logger.info(f"SIGNATUR-PRÜFUNG: {status}")
        self.logger.debug(f"  Issuer: {issuer}")
        self.logger.debug(f"  Algorithmus: {algorithm}")
    
    def log_hash_verification(self, claim_name: str, disclosure: str,
                               computed_hash: str, found_in_sd: bool):
        """Loggt die Hash-Verifikation für eine Disclosure."""
        status = "✓ PASS" if found_in_sd else "✗ FAIL"
        self.logger.info(f"HASH-CHECK '{claim_name}': {status}")
        self.logger.debug(f"  Disclosure: {disclosure[:60]}...")
        self.logger.debug(f"  Berechneter Hash: {computed_hash}")
        self.logger.debug(f"  In _sd Array gefunden: {found_in_sd}")
    
    def log_kb_jwt_verification(self, passed: bool, nonce_match: bool, 
                                  audience_match: bool):
        """Loggt die Key-Binding JWT Prüfung."""
        status = "✓ PASS" if passed else "✗ FAIL"
        self.logger.info(f"KEY BINDING PRÜFUNG: {status}")
        self.logger.debug(f"  Nonce stimmt überein: {nonce_match}")
        self.logger.debug(f"  Audience stimmt überein: {audience_match}")
    
    def log_status_check(self, status_uri: str, index: int, bit_value: int):
        """Loggt die Status-List-Prüfung."""
        status = "GÜLTIG" if bit_value == 0 else "WIDERRUFEN"
        self.logger.info(f"STATUS CHECK: {status}")
        self.logger.debug(f"  Status List URI: {status_uri}")
        self.logger.debug(f"  Index: {index}")
        self.logger.debug(f"  Bit-Wert: {bit_value}")
    
    def log_verification_result(self, checks: List[Dict], all_passed: bool):
        """Loggt das finale Verifikationsergebnis."""
        result = "✓ VERIFIZIERT" if all_passed else "✗ ABGELEHNT"
        self.logger.info(f"VERIFICATION COMPLETE: {result}")
        self.logger.info("-" * 40)
        for check in checks:
            status = "PASS" if check["passed"] else "FAIL"
            self.logger.info(f"  [{status}] {check['name']}")
            if check.get("details"):
                self.logger.debug(f"       Details: {check['details']}")
        self.logger.info("-" * 40)
    
    def log_extracted_claims(self, claims: Dict[str, Any]):
        """Loggt die extrahierten Claims."""
        self.logger.info("EXTRAHIERTE CLAIMS (verifiziert):")
        for name, value in claims.items():
            self.logger.info(f"  {name}: {value}")
    
    def log_nonce_generated(self, nonce: str, session_id: str):
        """Loggt die Nonce-Generierung."""
        self.logger.info("NONCE GENERIERT (One-Time-Use)")
        self.logger.debug(f"  Nonce: {nonce}")
        self.logger.debug(f"  Session-ID: {session_id}")
    
    def log_nonce_consumed(self, nonce: str):
        """Loggt den Verbrauch einer Nonce."""
        self.logger.info(f"NONCE VERBRAUCHT: {nonce[:30]}...")


# ============================================================================
# Singleton-Instanzen für globalen Zugriff
# ============================================================================

# Diese werden erst bei Bedarf erstellt, um den logs-Ordner nicht
# unnötig zu überschreiben wenn die Komponente nicht gestartet wird

_issuer_logger: Optional[IssuerLogger] = None
_wallet_logger: Optional[WalletLogger] = None
_verifier_logger: Optional[VerifierLogger] = None


def get_issuer_logger() -> IssuerLogger:
    """Gibt den Issuer-Logger zurück (Singleton)."""
    global _issuer_logger
    if _issuer_logger is None:
        _issuer_logger = IssuerLogger()
    return _issuer_logger


def get_wallet_logger() -> WalletLogger:
    """Gibt den Wallet-Logger zurück (Singleton)."""
    global _wallet_logger
    if _wallet_logger is None:
        _wallet_logger = WalletLogger()
    return _wallet_logger


def get_verifier_logger() -> VerifierLogger:
    """Gibt den Verifier-Logger zurück (Singleton)."""
    global _verifier_logger
    if _verifier_logger is None:
        _verifier_logger = VerifierLogger()
    return _verifier_logger
