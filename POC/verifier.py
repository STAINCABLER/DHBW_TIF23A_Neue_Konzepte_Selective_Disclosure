"""
SD-JWT Verifier Server
Prüft Verifiable Credentials (Türsteher/Polizei)

Features:
- SD-JWT Signaturprüfung
- Disclosure Hash Verifikation
- Key Binding JWT Validierung
- Status List Prüfung (Revocation Check)
- ASCII QR-Code für Verification Requests
"""

import os
import sys
import json
import secrets
import threading
import socket
import time
import argparse
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple

from flask import Flask, request, jsonify
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import print as rprint
import requests
import segno

import sd_jwt_utils as sdjwt
from log_manager import VerificationLogic, show_separator, show_inspection_mode_banner
from config_manager import ComponentConfig
from logger_config import get_verifier_logger

# SSL-Warnungen unterdrücken (nur für PoC!)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================================
# Konfiguration (wird beim Start geladen/erstellt)
# ============================================================================

CONFIG: Dict[str, Any] = {}

def load_config():
    """Lädt oder erstellt die Verifier-Konfiguration."""
    global CONFIG, TRUST_REGISTRY
    config_mgr = ComponentConfig("verifier")
    config = config_mgr.load_or_setup()
    
    # Für Rückwärtskompatibilität: flache Keys
    CONFIG = {
        "verifier_name": config.get("verifier_name", "Altersverifikation Service"),
        "verifier_uri": config.get("verifier_uri", "http://sd-verifier.ltm-labs.de:5002"),
        "host": config.get("host", "0.0.0.0"),
        "port": config.get("port", 5002),
        "ssl_cert": config.get("ssl", {}).get("cert_file", "certs/verifier.crt"),
        "ssl_key": config.get("ssl", {}).get("key_file", "certs/verifier.key"),
        "ssl_enabled": config.get("ssl", {}).get("enabled", True),
        "challenge_validity_minutes": config.get("challenge_validity_minutes", 5),
        "trust_registry_file": config.get("trust_registry_file", "trusted_registry.json"),
        "clock_skew_seconds": config.get("clock_skew_seconds", 20),
        "inspection_mode": config.get("inspection_mode", True)
    }
    
    # Trust Registry neu laden mit konfiguriertem Pfad
    global TRUST_REGISTRY
    TRUST_REGISTRY = load_trust_registry(CONFIG.get("trust_registry_file", "trusted_registry.json"))
    
    # Trust Registry mit konfigurierten Issuern aktualisieren
    trusted_issuers = config.get("trusted_issuers", [])
    for issuer_uri in trusted_issuers:
        if issuer_uri not in TRUST_REGISTRY.get("issuers", {}):
            TRUST_REGISTRY["issuers"][issuer_uri] = {
                "name": "Konfiguriert",
                "fetch_from_metadata": True
            }

# Version 4.0: Trust Registry laden
def load_trust_registry(registry_file: str = "trusted_registry.json") -> Dict[str, Any]:
    """Lädt die Trust Registry aus JSON-Datei."""
    try:
        if os.path.exists(registry_file):
            with open(registry_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        print(f"[Warning] Trust Registry nicht ladbar: {e}")
    
    # Fallback: Default-Werte
    return {
        "issuers": {
            "https://issuer.example.com": {"name": "Default", "fetch_from_metadata": True},
            "http://localhost:5001": {"name": "Local Issuer", "fetch_from_metadata": True}
        }
    }

# Initial leere Registry (wird in load_config() geladen)
TRUST_REGISTRY: Dict[str, Any] = {"issuers": {}}

# ============================================================================
# Globale Variablen
# ============================================================================

console = Console()
app = Flask(__name__)

# In-Memory Storage
pending_challenges: Dict[str, Dict] = {}  # nonce -> {created_at, state}
issuer_keys_cache: Dict[str, bytes] = {}  # issuer_uri -> public_key
short_codes: Dict[str, str] = {}  # Version 4.0: Short-Code -> nonce

# ============================================================================
# Issuer Key Caching
# ============================================================================

def fetch_issuer_public_key(issuer_uri: str) -> Optional[bytes]:
    """
    Holt den Public Key des Issuers.
    
    Version 4.0: Prüft zuerst Trust Registry für vorkonfigurierten Key,
    dann Fallback auf Metadata-Abruf.
    """
    if issuer_uri in issuer_keys_cache:
        return issuer_keys_cache[issuer_uri]
    
    # Version 4.0: Prüfe Trust Registry für vordefinierten Key
    issuer_info = TRUST_REGISTRY.get("issuers", {}).get(issuer_uri, {})
    predefined_key = issuer_info.get("public_key")
    
    if predefined_key and predefined_key != "null":
        try:
            console.print(f"[cyan]...[/cyan] Verwende Key aus Trust Registry")
            public_key = sdjwt.base64_to_key(predefined_key)
            issuer_keys_cache[issuer_uri] = public_key
            console.print(f"[green]✓[/green] Key aus Trust Registry geladen")
            return public_key
        except Exception as e:
            console.print(f"[yellow]![/yellow] Trust Registry Key ungültig: {e}")
    
    # Fallback: Von Metadata holen
    if not issuer_info.get("fetch_from_metadata", True):
        console.print(f"[red]✗[/red] Kein Key in Trust Registry und fetch_from_metadata=false")
        return None
    
    try:
        console.print(f"[cyan]...[/cyan] Hole Issuer-Key von {issuer_uri}")
        
        response = requests.get(
            f"{issuer_uri}/.well-known/openid-credential-issuer",
            verify=False,
            timeout=10
        )
        
        if response.status_code != 200:
            console.print(f"[red]✗[/red] Konnte Issuer-Metadata nicht abrufen")
            return None
        
        metadata = response.json()
        jwks = metadata.get("jwks", {})
        keys = jwks.get("keys", [])
        
        if not keys:
            console.print(f"[red]✗[/red] Keine Keys in Issuer-Metadata")
            return None
        
        # Ersten Ed25519 Key nehmen
        for key in keys:
            if key.get("crv") == "Ed25519":
                x = key.get("x", "")
                public_key = sdjwt.base64_to_key(x)
                issuer_keys_cache[issuer_uri] = public_key
                console.print(f"[green]✓[/green] Issuer-Key gecached")
                return public_key
        
        console.print(f"[red]✗[/red] Kein Ed25519 Key gefunden")
        return None
        
    except Exception as e:
        console.print(f"[red]✗[/red] Fehler beim Abrufen des Issuer-Keys: {e}")
        return None


def check_revocation_status(issuer_uri: str, status_index: int) -> Tuple[bool, str]:
    """
    Prüft den Revocation-Status eines Credentials.
    
    Returns:
        Tuple[bool, str]: (is_valid, message)
            - is_valid: True wenn NICHT widerrufen
    """
    try:
        response = requests.get(
            f"{issuer_uri}/status",
            verify=False,
            timeout=10
        )
        
        if response.status_code != 200:
            return True, "Status List nicht verfügbar (Credential wird als gültig angenommen)"
        
        status_data = response.json()
        status_list_b64 = status_data.get("status_list", "")
        
        if not status_list_b64:
            return True, "Leere Status List"
        
        status_list = sdjwt.base64_to_status_list(status_list_b64)
        is_revoked = sdjwt.get_status(status_list, status_index)
        
        if is_revoked:
            return False, f"Credential widerrufen (Index {status_index})"
        else:
            return True, f"Credential aktiv (Index {status_index})"
            
    except Exception as e:
        return True, f"Status-Prüfung fehlgeschlagen: {e}"


# ============================================================================
# Flask Endpunkte
# ============================================================================

@app.route('/challenge', methods=['GET'])
def challenge_endpoint():
    """Generiert eine Challenge (Nonce) für die Präsentation."""
    console.print("[blue]→[/blue] Challenge angefordert")
    
    nonce = secrets.token_urlsafe(24)
    state = secrets.token_urlsafe(16)
    
    pending_challenges[nonce] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "state": state
    }
    
    console.print(f"[green]✓[/green] Challenge erstellt: {nonce[:20]}...")
    
    # Version 5.0: File-Logging
    file_logger = get_verifier_logger()
    file_logger.log_nonce_generated(nonce, state)
    
    return jsonify({
        "nonce": nonce,
        "state": state,
        "audience": CONFIG["verifier_uri"],
        "expires_in": CONFIG["challenge_validity_minutes"] * 60
    })


@app.route('/verify', methods=['POST'])
def verify_endpoint():
    """
    Verifiziert eine SD-JWT Präsentation.
    
    Erwartet:
        - presentation: SD-JWT + Disclosures + KB-JWT im Format:
          <SD-JWT>~<Disclosure1>~...~<KB-JWT>
    """
    console.print("[blue]→[/blue] Präsentation empfangen")
    
    data = request.get_json() or {}
    presentation = data.get("presentation", "")
    
    if not presentation:
        return jsonify({"valid": False, "error": "No presentation provided"}), 400
    
    # Version 3.0: Verification Logic für Checklist
    verification = VerificationLogic() if CONFIG.get("inspection_mode", False) else None
    
    try:
        # Präsentation parsen
        sd_jwt, disclosures, kb_jwt = sdjwt.parse_presentation(presentation)
        
        console.print(f"[cyan]...[/cyan] SD-JWT: {sd_jwt[:50]}...")
        console.print(f"[cyan]...[/cyan] {len(disclosures)} Disclosure(s)")
        
        # Version 5.0: File-Logging für empfangene Präsentation
        file_logger = get_verifier_logger()
        file_logger.log_presentation_received(
            sd_jwt_preview=sd_jwt[:80],
            disclosures_count=len(disclosures),
            has_kb_jwt=bool(kb_jwt)
        )
        
        # Version 3.0: Incoming Presentation anzeigen
        if verification:
            show_separator("VERIFICATION PROCESS")
            verification.show_incoming_presentation(sd_jwt, disclosures, kb_jwt)
        
        # 1. SD-JWT Payload extrahieren
        sd_jwt_payload = sdjwt.get_jwt_payload(sd_jwt)
        issuer = sd_jwt_payload.get("iss", "")
        
        # 2. Issuer prüfen (Trust Registry v4.0)
        issuer_trusted = issuer in TRUST_REGISTRY.get("issuers", {})
        issuer_info = TRUST_REGISTRY.get("issuers", {}).get(issuer, {})
        issuer_name = issuer_info.get("name", "Unbekannt") if issuer_info else "Unbekannt"
        if verification:
            verification.add_check("Issuer vertrauenswürdig", issuer_trusted, f"{issuer_name} ({issuer})")
        
        if not issuer_trusted:
            console.print(f"[red]✗[/red] Issuer nicht vertrauenswürdig: {issuer}")
            if verification:
                verification.show_checklist()
            return jsonify({
                "valid": False,
                "error": f"Untrusted issuer: {issuer}"
            })
        
        console.print(f"[green]✓[/green] Issuer vertrauenswürdig")
        
        # 3. Issuer Public Key holen
        issuer_public_key = fetch_issuer_public_key(issuer)
        if not issuer_public_key:
            if verification:
                verification.add_check("Issuer Key abrufbar", False, "Fehler beim Abruf")
                verification.show_checklist()
            return jsonify({
                "valid": False,
                "error": "Could not fetch issuer public key"
            })
        
        issuer_pub_key_obj = sdjwt.load_public_key(issuer_public_key)
        
        # 4. SD-JWT Signatur prüfen
        sig_valid = sdjwt.verify_jwt_signature(sd_jwt, issuer_pub_key_obj)
        if verification:
            verification.add_check("Issuer Signatur (EdDSA)", sig_valid, "Ed25519 Kurve")
        
        if not sig_valid:
            console.print("[red]✗[/red] Issuer-Signatur ungültig!")
            if verification:
                verification.show_checklist()
            return jsonify({
                "valid": False,
                "error": "Invalid issuer signature"
            })
        
        console.print("[green]✓[/green] Issuer-Signatur gültig")
        
        # 5. Disclosures validieren und Claims extrahieren
        valid, extracted_claims, error = sdjwt.validate_sd_jwt(
            sd_jwt, disclosures, issuer_pub_key_obj
        )
        
        # Version 3.0: Hash-Verifikation anzeigen
        if verification:
            sd_array = sd_jwt_payload.get("_sd", [])
            for disclosure in disclosures:
                try:
                    _, claim_name, _ = sdjwt.decode_disclosure(disclosure)
                    computed_hash = sdjwt.hash_disclosure(disclosure)
                    found = computed_hash in sd_array
                    verification.show_hash_verification(claim_name, disclosure, computed_hash, found)
                except:
                    pass
            verification.add_check("Disclosure-Hashes", valid, f"{len(disclosures)} geprüft")
        
        if not valid:
            console.print(f"[red]✗[/red] Disclosure-Validierung fehlgeschlagen: {error}")
            if verification:
                verification.show_checklist()
            return jsonify({
                "valid": False,
                "error": error
            })
        
        console.print(f"[green]✓[/green] {len(extracted_claims)} Claim(s) extrahiert")
        
        # 6. Holder Public Key aus cnf extrahieren
        holder_public_key = sdjwt.extract_holder_public_key(sd_jwt)
        holder_pub_key_obj = sdjwt.load_public_key(holder_public_key)
        
        # 7. KB-JWT Payload extrahieren
        kb_payload = sdjwt.get_jwt_payload(kb_jwt)
        nonce = kb_payload.get("nonce", "")
        
        # 8. Nonce prüfen
        nonce_valid = nonce in pending_challenges
        if nonce_valid:
            challenge_data = pending_challenges[nonce]
            created_at = datetime.fromisoformat(challenge_data["created_at"]).replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - created_at > timedelta(minutes=CONFIG["challenge_validity_minutes"]):
                pending_challenges.pop(nonce)
                nonce_valid = False
        
        if verification:
            verification.add_check("Nonce gültig", nonce_valid, nonce[:20] + "..." if nonce else "-")
        
        if not nonce_valid:
            console.print("[red]✗[/red] Ungültige oder abgelaufene Nonce")
            if verification:
                verification.show_checklist()
            return jsonify({
                "valid": False,
                "error": "Invalid or expired nonce"
            })
        
        # Nonce nach Verwendung löschen
        pending_challenges.pop(nonce)
        console.print("[green]✓[/green] Nonce gültig")
        
        # 9. KB-JWT Signatur prüfen
        kb_sig_valid = sdjwt.verify_jwt_signature(kb_jwt, holder_pub_key_obj)
        if verification:
            verification.add_check("KB-JWT Signatur (Holder)", kb_sig_valid, "Proof of Possession")
        
        if not kb_sig_valid:
            console.print("[red]✗[/red] Key Binding Signatur ungültig!")
            if verification:
                verification.show_checklist()
            return jsonify({
                "valid": False,
                "error": "Invalid key binding signature"
            })
        
        console.print("[green]✓[/green] Key Binding Signatur gültig")
        
        # 10. SD-Hash im KB-JWT prüfen
        expected_sd_hash = sdjwt.base64url_encode(
            __import__('hashlib').sha256(sd_jwt.encode('ascii')).digest()
        )
        sd_hash_valid = kb_payload.get("sd_hash") == expected_sd_hash
        if verification:
            verification.add_check("SD-Hash Bindung", sd_hash_valid, "KB-JWT bindet an SD-JWT")
        
        if not sd_hash_valid:
            console.print("[red]✗[/red] SD-Hash stimmt nicht überein")
            if verification:
                verification.show_checklist()
            return jsonify({
                "valid": False,
                "error": "SD-Hash mismatch"
            })
        
        console.print("[green]✓[/green] SD-Hash korrekt")
        
        # 11. Revocation Status prüfen
        status_info = sdjwt.extract_status_info(sd_jwt)
        revocation_status = "Nicht prüfbar (kein Status-Claim)"
        status_valid = True
        
        if status_info:
            status_index, status_uri = status_info
            status_valid, status_message = check_revocation_status(issuer, status_index)
            revocation_status = status_message
            
            # Version 3.0: Status Check anzeigen
            if verification:
                # Hole Bit-Wert für Anzeige
                try:
                    response = requests.get(f"{issuer}/status", verify=False, timeout=5)
                    if response.status_code == 200:
                        status_data = response.json()
                        status_list = sdjwt.base64_to_status_list(status_data.get("status_list", ""))
                        bit_value = 1 if sdjwt.get_status(status_list, status_index) else 0
                        verification.show_status_check(status_index, f"{issuer}/status", bit_value)
                except:
                    pass
                verification.add_check("Revocation Status", status_valid, revocation_status)
            
            if not status_valid:
                console.print(f"[red]✗[/red] {status_message}")
                if verification:
                    verification.show_checklist()
                return jsonify({
                    "valid": False,
                    "error": status_message,
                    "revoked": True
                })
        
        console.print(f"[green]✓[/green] Status: {revocation_status}")
        
        # Version 5.0: File-Logging für erfolgreiche Verifikation
        file_logger = get_verifier_logger()
        file_logger.log_verification_result(
            checks=verification.checks if verification else [],
            all_passed=True
        )
        file_logger.log_extracted_claims(extracted_claims)
        
        # Version 3.0: Finale Checkliste anzeigen
        if verification:
            verification.show_checklist()
            verification.show_extracted_claims(extracted_claims)
        else:
            # Erfolg! Claims anzeigen (normale Anzeige)
            console.print("")
            show_verified_claims(extracted_claims, issuer, revocation_status)
        
        return jsonify({
            "valid": True,
            "issuer": issuer,
            "claims": extracted_claims,
            "holder_verified": True,
            "status": revocation_status
        })
        
    except Exception as e:
        console.print(f"[red]✗[/red] Verifikationsfehler: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "valid": False,
            "error": str(e)
        })


@app.route('/health', methods=['GET'])
def health():
    """Health Check."""
    return jsonify({"status": "ok", "verifier": CONFIG["verifier_name"]})


@app.route('/shortcode/<code>', methods=['GET'])
def resolve_shortcode(code: str):
    """
    Version 4.0: Short-Code zu Nonce auflösen.
    Ermöglicht einfache Eingabe einer 6-stelligen Zahl statt langer URIs.
    """
    if code in short_codes:
        nonce = short_codes[code]
        if nonce in pending_challenges:
            challenge = pending_challenges[nonce]
            console.print(f"[cyan]...[/cyan] Short-Code {code} aufgelöst")
            return jsonify({
                "found": True,
                "nonce": nonce,
                "state": challenge.get("state"),
                "verifier_uri": CONFIG["verifier_uri"]
            })
    
    return jsonify({
        "found": False,
        "error": f"Short-Code {code} nicht gefunden oder abgelaufen"
    }), 404


# ============================================================================
# Terminal UI
# ============================================================================

def show_verified_claims(claims: Dict, issuer: str, status: str):
    """Zeigt die verifizierten Claims schön an."""
    console.print(Panel(
        "[bold green]✓ VERIFIZIERUNG ERFOLGREICH[/bold green]",
        border_style="green"
    ))
    
    table = Table(title="Verifizierte Daten", expand=False, border_style="green")
    table.add_column("Attribut", style="cyan", no_wrap=True)
    table.add_column("Wert", style="white")
    
    for claim_name, claim_value in claims.items():
        # Schöne Claim-Namen
        display_name = claim_name.replace("_", " ").title()
        table.add_row(display_name, str(claim_value))
    
    console.print(table)
    
    console.print(f"\n[dim]Issuer: {issuer}[/dim]")
    console.print(f"[dim]Status: {status}[/dim]")


def show_failed_verification(error: str):
    """Zeigt eine fehlgeschlagene Verifikation an."""
    console.print(Panel(
        f"[bold red]✗ VERIFIZIERUNG FEHLGESCHLAGEN[/bold red]\n\n"
        f"Fehler: {error}",
        border_style="red"
    ))


def create_verification_request():
    """Erstellt einen Verification Request mit QR-Code und Short-Code (v4.0)."""
    nonce = secrets.token_urlsafe(24)
    state = secrets.token_urlsafe(16)
    
    pending_challenges[nonce] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "state": state
    }
    
    # Request URI erstellen
    request_uri = f"openid-verification://?verifier={CONFIG['verifier_uri']}&nonce={nonce}&state={state}"
    
    # Version 7.0: Short-Code generieren (6-stellig)
    short_code = str(secrets.randbelow(1000000)).zfill(6)
    while short_code in short_codes:  # Kollisionen vermeiden
        short_code = str(secrets.randbelow(1000000)).zfill(6)
    short_codes[short_code] = nonce
    
    console.print(Panel(
        f"[bold]Verification Request[/bold]\n\n"
        f"Nonce: [cyan]{nonce[:30]}...[/cyan]\n"
        f"[bold yellow]Short-Code: {short_code}[/bold yellow]  ← Einfache Eingabe in Wallet\n"
        f"Gültig für: {CONFIG['challenge_validity_minutes']} Minuten",
        title="🔍 Verification Request",
        border_style="blue"
    ))
    
    # QR-Code anzeigen
    try:
        qr = segno.make(request_uri)
        console.print("\n[bold]QR-Code zum Scannen:[/bold]")
        qr.terminal(compact=True)
    except Exception:
        pass
    
    console.print(f"\n[dim]URI: {request_uri}[/dim]")
    console.print(f"\n[yellow]Warte auf Präsentation... (Short-Code: {short_code})[/yellow]")


def show_pending_challenges():
    """Zeigt offene Challenges an."""
    if not pending_challenges:
        console.print("[yellow]Keine offenen Challenges[/yellow]")
        return
    
    table = Table(title="Offene Challenges", expand=False)
    table.add_column("Nonce (gekürzt)", style="cyan")
    table.add_column("Erstellt", style="green")
    table.add_column("Status", style="yellow")
    
    now = datetime.now(timezone.utc)
    
    for nonce, data in pending_challenges.items():
        created_at = datetime.fromisoformat(data["created_at"]).replace(tzinfo=timezone.utc)
        age_minutes = (now - created_at).total_seconds() / 60
        
        if age_minutes > CONFIG["challenge_validity_minutes"]:
            status = "[red]Abgelaufen[/red]"
        else:
            remaining = CONFIG["challenge_validity_minutes"] - age_minutes
            status = f"[green]{remaining:.1f} min verbleibend[/green]"
        
        table.add_row(
            nonce[:30] + "...",
            created_at.strftime("%H:%M:%S"),
            status
        )
    
    console.print(table)


def show_help():
    """Zeigt Hilfe an."""
    help_text = """
[bold]Verfügbare Befehle:[/bold]

  [cyan]request[/cyan]      Erstellt einen neuen Verification Request
               mit QR-Code zum Scannen
  
  [cyan]challenges[/cyan]   Zeigt offene Challenges an
  
  [cyan]clear[/cyan]        Löscht abgelaufene Challenges
  
  [cyan]status[/cyan]       Zeigt Server-Status
  
  [cyan]help[/cyan]         Zeigt diese Hilfe
  
  [cyan]exit[/cyan]         Beendet den Server
"""
    console.print(Panel(help_text, title="Hilfe", border_style="blue"))


def clear_expired_challenges():
    """Löscht abgelaufene Challenges."""
    now = datetime.now(timezone.utc)
    expired = []
    
    for nonce, data in pending_challenges.items():
        created_at = datetime.fromisoformat(data["created_at"]).replace(tzinfo=timezone.utc)
        if (now - created_at).total_seconds() / 60 > CONFIG["challenge_validity_minutes"]:
            expired.append(nonce)
    
    for nonce in expired:
        pending_challenges.pop(nonce)
    
    console.print(f"[green]✓[/green] {len(expired)} abgelaufene Challenge(s) gelöscht")


def command_loop():
    """Terminal-Befehlsschleife."""
    # Version 7.0: Hilfe automatisch beim Start anzeigen
    show_help()
    
    while True:
        try:
            cmd = Prompt.ask("[bold blue]verifier>[/bold blue]")
            command = cmd.strip().lower()
            
            if not command:
                continue
            
            if command in ["request", "r", "new"]:
                create_verification_request()
            
            elif command in ["challenges", "c", "pending"]:
                show_pending_challenges()
            
            elif command == "clear":
                clear_expired_challenges()
            
            elif command == "status":
                console.print(f"[green]●[/green] Server läuft auf Port {CONFIG['port']}")
                console.print(f"[green]●[/green] {len(pending_challenges)} offene Challenge(s)")
                console.print(f"[green]●[/green] {len(issuer_keys_cache)} gecachte Issuer-Keys")
            
            elif command in ["help", "h", "?"]:
                show_help()
            
            elif command in ["exit", "quit", "q"]:
                console.print("[yellow]Server wird beendet...[/yellow]")
                os._exit(0)
            
            else:
                console.print(f"[red]Unbekannter Befehl: {command}[/red]")
                console.print("[dim]Tippe 'help' für Hilfe[/dim]")
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Server wird beendet...[/yellow]")
            break
        except Exception as e:
            console.print(f"[red]Fehler: {e}[/red]")


# ============================================================================
# Main
# ============================================================================

def renew_certificates():
    """Erneuert TLS-Zertifikate via ACME/Certbot (Version 6.0)."""
    console.print(Panel(
        "[bold]TLS-Zertifikats-Erneuerung[/bold]\n\n"
        "Starte ACME/Let's Encrypt Zertifikatserneuerung...",
        title="\U0001f510 Certificate Renewal",
        border_style="cyan"
    ))
    
    try:
        # Versuche cert_manager zu importieren
        from cert_manager import AcmeCertManager, generate_self_signed_cert
        
        # Lade Konfiguration
        load_config()
        
        config_path = os.path.join(os.path.dirname(__file__), "certs/acme_config.json")
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                acme_config = json.load(f)
            
            if acme_config.get('cloudflare_token'):
                manager = AcmeCertManager(use_staging=acme_config.get('staging', True))
                
                if manager.setup_cloudflare(acme_config['cloudflare_token']):
                    if manager.register_account(acme_config.get('email', '')):
                        # Zertifikat für Verifier erneuern
                        domain = CONFIG.get('verifier_uri', 'localhost').replace('https://', '').split(':')[0]
                        
                        success = manager.issue_certificate(
                            domain=domain,
                            cert_path=CONFIG['ssl_cert'],
                            key_path=CONFIG['ssl_key']
                        )
                        
                        if success:
                            console.print("[green]✓[/green] Zertifikate erfolgreich erneuert!")
                            return True
        
        # Fallback: Selbstsigniertes Zertifikat
        console.print("[yellow]![/yellow] ACME nicht konfiguriert - erstelle selbstsigniertes Zertifikat")
        generate_self_signed_cert(
            domain="localhost",
            cert_path=CONFIG.get('ssl_cert', 'certs/verifier.crt'),
            key_path=CONFIG.get('ssl_key', 'certs/verifier.key')
        )
        console.print("[green]✓[/green] Selbstsigniertes Zertifikat erstellt")
        return True
        
    except ImportError:
        console.print("[red]✗[/red] cert_manager nicht verfügbar")
        console.print("[dim]Installiere: pip install acme josepy cloudflare cryptography[/dim]")
        return False
    except Exception as e:
        console.print(f"[red]✗[/red] Fehler bei Zertifikatserneuerung: {e}")
        return False


def main():
    """Hauptfunktion."""
    # Version 6.0: CLI-Argument Parser
    parser = argparse.ArgumentParser(
        description="SD-JWT Verifier Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Beispiele:\n"
               "  python verifier.py                # Server normal starten\n"
               "  python verifier.py --renew-certs  # Nur Zertifikate erneuern\n"
    )
    parser.add_argument(
        '--renew-certs',
        action='store_true',
        help='TLS-Zertifikate erneuern und beenden (ohne Server zu starten)'
    )
    args = parser.parse_args()
    
    # Wenn --renew-certs: Nur Zertifikate erneuern und beenden
    if args.renew_certs:
        load_config()  # Brauchen wir für Pfade
        success = renew_certificates()
        sys.exit(0 if success else 1)
    
    # Konfiguration laden (First-Run Setup falls nötig)
    load_config()
    
    # Version 5.0: File-Logger initialisieren
    file_logger = get_verifier_logger()
    file_logger.logger.info(f"Verifier Server gestartet - {CONFIG['verifier_name']}")
    
    console.print(Panel(
        f"[bold]{CONFIG['verifier_name']}[/bold]\n"
        "SD-JWT Credential Verifier\n"
        f"Version 7.0 - Port {CONFIG['port']}",
        title="\U0001f50d Verifier Server",
        border_style="blue"
    ))
    
    # Version 3.0: Inspection Mode Banner
    if CONFIG.get("inspection_mode", False):
        show_inspection_mode_banner()
        console.print("[dim]Deep-Trace Logging aktiv: logs/verifier_debug.log[/dim]\n")
    
    # Flask Server im Hintergrund starten
    console.print(f"\n[cyan]Starte Server auf Port {CONFIG['port']}...[/cyan]")
    
    # Prüfe ob SSL aktiviert und Zertifikate existieren
    ssl_enabled = CONFIG.get("ssl_enabled", True)
    use_ssl = ssl_enabled and os.path.exists(CONFIG["ssl_cert"]) and os.path.exists(CONFIG["ssl_key"])
    
    if use_ssl:
        ssl_context = (CONFIG["ssl_cert"], CONFIG["ssl_key"])
        console.print("[green]✓[/green] HTTPS aktiviert")
    else:
        ssl_context = None
        if ssl_enabled:
            console.print("[yellow]![/yellow] HTTPS deaktiviert (keine Zertifikate gefunden)")
            console.print(f"[dim]  Erwartet: {CONFIG['ssl_cert']} und {CONFIG['ssl_key']}[/dim]")
        else:
            console.print("[yellow]![/yellow] HTTPS deaktiviert (in Konfiguration)")
    
    # Trusted Issuers anzeigen (aus Trust Registry v4.0)
    console.print("[green]✓[/green] Vertrauenswürdige Issuer (Trust Registry):")
    for issuer_uri, issuer_info in TRUST_REGISTRY.get("issuers", {}).items():
        name = issuer_info.get("name", "Unbekannt")
        console.print(f"    [dim]• {name}: {issuer_uri}[/dim]")
    
    # Server Thread starten
    server_thread = threading.Thread(
        target=lambda: app.run(
            host=CONFIG["host"],
            port=CONFIG["port"],
            ssl_context=ssl_context,
            debug=False,
            use_reloader=False
        ),
        daemon=True
    )
    server_thread.start()

    host = CONFIG.get("host", "127.0.0.1")
    target_host = "127.0.0.1" if host in ["0.0.0.0", "::"] else host
    deadline = time.time() + 5.0
    server_ready = False

    while time.time() < deadline:
        try:
            with socket.create_connection((target_host, CONFIG["port"]), timeout=0.5):
                server_ready = True
                break
        except OSError:
            time.sleep(0.1)

    if server_ready:
        console.print("\n[bold green]Verifier bereit![/bold green]\n")
    else:
        console.print("\n[yellow]![/yellow] Serverstart verzögert, Konsole bleibt aktiv.\n")
    
    # Befehlsschleife starten
    command_loop()


if __name__ == "__main__":
    main()
