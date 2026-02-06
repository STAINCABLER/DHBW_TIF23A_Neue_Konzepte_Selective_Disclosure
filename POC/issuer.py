"""
SD-JWT Issuer Server
Behörde/Aussteller für Verifiable Credentials

Features:
- Pre-Authorized Code Flow (OID4VCI light)
- Bitstring Status List für Revocation
- ASCII QR-Code Offers im Terminal
- REST API mit Flask
"""

import os
import sys
import json
import secrets
import threading
import argparse
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from flask import Flask, request, jsonify
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import print as rprint
import segno

import sd_jwt_utils as sdjwt
from log_manager import crypto_insight, show_separator, show_inspection_mode_banner
from config_manager import ComponentConfig
from logger_config import get_issuer_logger

# ============================================================================
# Konfiguration (wird beim Start geladen/erstellt)
# ============================================================================

CONFIG: Dict[str, Any] = {}

def load_config():
    """Lädt oder erstellt die Issuer-Konfiguration."""
    global CONFIG
    config_mgr = ComponentConfig("issuer")
    config = config_mgr.load_or_setup()
    
    # Für Rückwärtskompatibilität: flache Keys
    CONFIG = {
        "issuer_name": config.get("issuer_name", "Bundesamt für Digitale Identität"),
        "issuer_uri": config.get("issuer_uri", "https://localhost:5001"),
        "host": config.get("host", "0.0.0.0"),
        "port": config.get("port", 5001),
        "ssl_cert": config.get("ssl", {}).get("cert_file", "certs/issuer.crt"),
        "ssl_key": config.get("ssl", {}).get("key_file", "certs/issuer.key"),
        "ssl_enabled": config.get("ssl", {}).get("enabled", True),
        "status_list_size": config.get("status_list_size", 1000),
        "citizen_db_path": config.get("citizen_db_path", "citizen_db.json"),
        "keys_path": config.get("keys_path", "issuer_keys.json"),
        "inspection_mode": config.get("inspection_mode", True),
        "add_decoys": config.get("add_decoys", True),
        "decoy_count": config.get("decoy_count", 2)
    }

# Version 4.0: Short-Code Storage für Offers
short_codes: Dict[str, str] = {}  # 4-stelliger Code -> full offer URI

# ============================================================================
# Globale Variablen
# ============================================================================

console = Console()
app = Flask(__name__)

# In-Memory Storage
issuer_keys: Dict[str, bytes] = {}
citizen_db: Dict[str, Dict] = {}
status_list: bytes = b''
pending_offers: Dict[str, Dict] = {}  # pre_auth_code -> {citizen_code, created_at}
access_tokens: Dict[str, Dict] = {}   # token -> {citizen_code, expires_at}
issued_credentials: Dict[str, int] = {}  # citizen_code -> status_index

# ============================================================================
# Initialisierung
# ============================================================================

def load_or_create_keys():
    """Lädt oder erstellt Issuer-Keys."""
    global issuer_keys
    
    keys_path = CONFIG["keys_path"]
    
    if os.path.exists(keys_path):
        with open(keys_path, 'r') as f:
            data = json.load(f)
            issuer_keys["private"] = sdjwt.base64_to_key(data["private"])
            issuer_keys["public"] = sdjwt.base64_to_key(data["public"])
        console.print("[green]✓[/green] Issuer-Keys geladen")
    else:
        priv, pub = sdjwt.generate_ed25519_keypair()
        issuer_keys["private"] = priv
        issuer_keys["public"] = pub
        
        with open(keys_path, 'w') as f:
            json.dump({
                "private": sdjwt.key_to_base64(priv),
                "public": sdjwt.key_to_base64(pub)
            }, f, indent=2)
        console.print("[green]✓[/green] Neue Issuer-Keys generiert")


def load_citizen_db():
    """Lädt die Bürgerdatenbank."""
    global citizen_db
    
    db_path = CONFIG["citizen_db_path"]
    
    if os.path.exists(db_path):
        with open(db_path, 'r', encoding='utf-8') as f:
            citizen_db = json.load(f)
        console.print(f"[green]✓[/green] Bürgerdatenbank geladen: {len(citizen_db)} Einträge")
    else:
        # Demo-Daten erstellen
        citizen_db = {
            "1234-CODE": {
                "given_name": "Max",
                "family_name": "Mustermann",
                "birthdate": "1990-01-15",
                "address": "Musterstraße 42, 12345 Berlin",
                "nationality": "DE",
                "document_number": "T220001234"
            },
            "5678-CODE": {
                "given_name": "Erika",
                "family_name": "Musterfrau",
                "birthdate": "1985-07-22",
                "address": "Beispielweg 7, 80331 München",
                "nationality": "DE",
                "document_number": "T220005678"
            },
            "9999-CODE": {
                "given_name": "Hans",
                "family_name": "Schmidt",
                "birthdate": "1978-11-03",
                "address": "Hauptstraße 1, 50667 Köln",
                "nationality": "DE",
                "document_number": "T220009999"
            }
        }
        
        with open(db_path, 'w', encoding='utf-8') as f:
            json.dump(citizen_db, f, indent=2, ensure_ascii=False)
        console.print(f"[yellow]![/yellow] Demo-Bürgerdatenbank erstellt: {db_path}")


def init_status_list():
    """Initialisiert die Status List für Revocation."""
    global status_list
    status_list = sdjwt.create_status_list(CONFIG["status_list_size"])
    console.print(f"[green]✓[/green] Status List initialisiert ({CONFIG['status_list_size']} Einträge)")


# ============================================================================
# Flask Endpunkte
# ============================================================================

@app.route('/.well-known/openid-credential-issuer', methods=['GET'])
def metadata():
    """Liefert Issuer Metadata (Public Keys, unterstützte Credentials)."""
    console.print("[blue]→[/blue] Metadata angefordert")
    
    return jsonify({
        "issuer": CONFIG["issuer_uri"],
        "credential_issuer": CONFIG["issuer_uri"],
        "credential_endpoint": f"{CONFIG['issuer_uri']}/credential",
        "token_endpoint": f"{CONFIG['issuer_uri']}/token",
        "status_list_endpoint": f"{CONFIG['issuer_uri']}/status",
        "jwks": {
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": sdjwt.key_to_base64(issuer_keys["public"]),
                "use": "sig",
                "kid": "issuer-key-1"
            }]
        },
        "credentials_supported": [{
            "format": "sd_jwt_vc",
            "type": "IdentityCredential",
            "claims": ["given_name", "family_name", "birthdate", "address", "nationality", "document_number"]
        }]
    })


@app.route('/token', methods=['POST'])
def token_endpoint():
    """Token-Endpunkt für Pre-Authorized Code Flow."""
    console.print("[blue]→[/blue] Token-Anfrage empfangen")
    
    data = request.get_json() or {}
    grant_type = data.get("grant_type")
    pre_auth_code = data.get("pre-authorized_code")
    
    if grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        console.print("[red]✗[/red] Ungültiger grant_type")
        return jsonify({"error": "unsupported_grant_type"}), 400
    
    if pre_auth_code not in pending_offers:
        console.print("[red]✗[/red] Ungültiger Pre-Auth Code")
        return jsonify({"error": "invalid_grant"}), 400
    
    offer = pending_offers.pop(pre_auth_code)
    
    # Prüfe Ablauf (5 Minuten)
    created_at = datetime.fromisoformat(offer["created_at"])
    if datetime.utcnow() - created_at > timedelta(minutes=5):
        console.print("[red]✗[/red] Pre-Auth Code abgelaufen")
        return jsonify({"error": "invalid_grant", "error_description": "Code expired"}), 400
    
    # Access Token erstellen
    access_token = secrets.token_urlsafe(32)
    access_tokens[access_token] = {
        "citizen_code": offer["citizen_code"],
        "expires_at": (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    }
    
    console.print(f"[green]✓[/green] Access Token erstellt für {offer['citizen_code']}")
    
    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 600,
        "c_nonce": secrets.token_urlsafe(16),
        "c_nonce_expires_in": 300
    })


@app.route('/credential', methods=['POST'])
def credential_endpoint():
    """Credential-Endpunkt - erstellt SD-JWT."""
    console.print("[blue]→[/blue] Credential-Anfrage empfangen")
    
    # Authorization prüfen
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        console.print("[red]✗[/red] Kein Bearer Token")
        return jsonify({"error": "invalid_token"}), 401
    
    access_token = auth_header[7:]
    if access_token not in access_tokens:
        console.print("[red]✗[/red] Ungültiger Access Token")
        return jsonify({"error": "invalid_token"}), 401
    
    token_data = access_tokens[access_token]
    
    # Token-Ablauf prüfen
    expires_at = datetime.fromisoformat(token_data["expires_at"])
    if datetime.utcnow() > expires_at:
        access_tokens.pop(access_token)
        console.print("[red]✗[/red] Access Token abgelaufen")
        return jsonify({"error": "invalid_token", "error_description": "Token expired"}), 401
    
    citizen_code = token_data["citizen_code"]
    
    # Request Body parsen
    data = request.get_json() or {}
    proof = data.get("proof", {})
    
    if proof.get("proof_type") != "jwt":
        console.print("[red]✗[/red] Ungültiger Proof Type")
        return jsonify({"error": "invalid_proof"}), 400
    
    proof_jwt = proof.get("jwt", "")
    
    # Proof validieren (vereinfacht - extrahiert nur den Public Key)
    try:
        proof_payload = sdjwt.get_jwt_payload(proof_jwt)
        proof_header = sdjwt.get_jwt_header(proof_jwt)
        
        # Extrahiere Holder Public Key aus Proof Header (jwk)
        jwk = proof_header.get("jwk", {})
        holder_public_key_b64 = jwk.get("x", "")
        holder_public_key = sdjwt.base64_to_key(holder_public_key_b64)
        
        # Verifiziere die Proof-Signatur
        holder_pub_key_obj = sdjwt.load_public_key(holder_public_key)
        if not sdjwt.verify_jwt_signature(proof_jwt, holder_pub_key_obj):
            console.print("[red]✗[/red] Proof Signatur ungültig")
            return jsonify({"error": "invalid_proof"}), 400
            
    except Exception as e:
        console.print(f"[red]✗[/red] Proof Fehler: {e}")
        return jsonify({"error": "invalid_proof"}), 400
    
    # Bürgerdaten abrufen
    if citizen_code not in citizen_db:
        console.print(f"[red]✗[/red] Bürger nicht gefunden: {citizen_code}")
        return jsonify({"error": "invalid_request"}), 400
    
    citizen_data = citizen_db[citizen_code]
    
    # Status Index zuweisen (falls noch nicht vorhanden)
    if citizen_code not in issued_credentials:
        # Finde nächsten freien Index
        used_indices = set(issued_credentials.values())
        for i in range(CONFIG["status_list_size"]):
            if i not in used_indices:
                issued_credentials[citizen_code] = i
                break
    
    status_index = issued_credentials.get(citizen_code, 0)
    
    # =========================================================================
    # VERSION 3.0: CRYPTO-INSIGHT LOGGING
    # =========================================================================
    
    if CONFIG.get("inspection_mode", False):
        show_separator("CRYPTO-INSIGHT: SD-JWT ERSTELLUNG")
        
        # Schritt 1: Rohdaten anzeigen
        crypto_insight.show_raw_data(citizen_code, citizen_data)
    
    # SD-JWT erstellen mit detailliertem Logging
    console.print("[cyan]...[/cyan] Erstelle SD-JWT...")
    
    issuer_private_key = sdjwt.load_private_key(issuer_keys["private"])
    
    # Manuelle Erstellung für Inspection Mode
    if CONFIG.get("inspection_mode", False):
        # Disclosures einzeln erstellen mit Logging
        sd_array = []
        disclosures = []
        disclosure_map = {}
        
        for claim_name, claim_value in citizen_data.items():
            salt = sdjwt.generate_salt()
            
            # Schritt 2: Salting anzeigen
            disclosure_array = [salt, claim_name, claim_value]
            crypto_insight.show_salting(claim_name, claim_value, salt, disclosure_array)
            
            # Disclosure erstellen
            digest, encoded_disclosure = sdjwt.create_disclosure(claim_name, claim_value, salt)
            
            # Schritt 3: Hashing anzeigen
            crypto_insight.show_hashing(claim_name, encoded_disclosure, digest)
            
            sd_array.append(digest)
            disclosures.append(encoded_disclosure)
            disclosure_map[claim_name] = encoded_disclosure
        
        # Version 4.0: Decoy-Hashes hinzufügen
        if CONFIG.get("add_decoys", False):
            decoy_count = CONFIG.get("decoy_count", 2)
            decoy_hashes = sdjwt.generate_decoy_hashes(decoy_count)
            sd_array.extend(decoy_hashes)
            # Mische Array um Decoys nicht erkennbar zu machen
            import random
            random.shuffle(sd_array)
            console.print(f"[cyan]...[/cyan] {decoy_count} Decoy-Hashes hinzugefügt (Anti-Profiling)")
        
        # Payload erstellen
        from datetime import datetime, timedelta
        now = datetime.utcnow()
        exp = now + timedelta(days=365)
        
        payload = {
            "iss": CONFIG["issuer_uri"],
            "sub": f"citizen:{citizen_code}",
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "_sd": sd_array,
            "_sd_alg": "sha-256",
            "cnf": {
                "jwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": sdjwt.key_to_base64(holder_public_key)
                }
            },
            "status": {
                "status_list": {
                    "idx": status_index,
                    "uri": f"{CONFIG['issuer_uri']}/status"
                }
            }
        }
        
        # Schritt 4: Token-Struktur anzeigen
        crypto_insight.show_token_structure(payload, len(sd_array))
        
        # Signieren
        header = sdjwt.create_jwt_header(typ="sd+jwt")
        sd_jwt = sdjwt.sign_jwt(header, payload, issuer_private_key)
        
        # Schritt 5: Signatur anzeigen
        crypto_insight.show_signature(
            "EdDSA (Ed25519)", 
            sdjwt.key_to_base64(issuer_keys["public"])
        )
        
        show_separator()
    else:
        # Standard-Erstellung ohne detailliertes Logging
        sd_jwt, disclosures, disclosure_map = sdjwt.create_sd_jwt(
            claims=citizen_data,
            issuer_private_key=issuer_private_key,
            holder_public_key=holder_public_key,
            issuer=CONFIG["issuer_uri"],
            subject=f"citizen:{citizen_code}",
            status_index=status_index,
            status_uri=f"{CONFIG['issuer_uri']}/status",
            add_decoys=CONFIG.get("add_decoys", False),  # Version 4.0
            decoy_count=CONFIG.get("decoy_count", 2)
        )
    
    console.print(f"[green]✓[/green] SD-JWT erstellt für {citizen_data['given_name']} {citizen_data['family_name']}")
    
    # Version 5.0: File-Logging
    file_logger = get_issuer_logger()
    file_logger.log_credential_issued(citizen_code, status_index)
    file_logger.logger.debug(f"SD-JWT Länge: {len(sd_jwt)} Zeichen")
    file_logger.logger.debug(f"Anzahl Disclosures: {len(disclosures)}")
    
    # Token nach Verwendung löschen
    access_tokens.pop(access_token)
    
    # Zeige Zusammenfassung
    table = Table(title="Ausgestelltes Credential", expand=False)
    table.add_column("Claim", style="cyan")
    table.add_column("Wert", style="green")
    
    for claim, value in citizen_data.items():
        table.add_row(claim, str(value))
    
    table.add_row("Status Index", str(status_index), style="dim")
    console.print(table)
    
    return jsonify({
        "format": "sd_jwt_vc",
        "credential": sd_jwt,
        "disclosures": disclosures,
        "disclosure_mapping": disclosure_map
    })


@app.route('/status', methods=['GET'])
def status_endpoint():
    """Gibt die Status List zurück."""
    console.print("[blue]→[/blue] Status List angefordert")
    
    return jsonify({
        "status_list": sdjwt.status_list_to_base64(status_list),
        "bits": 1,  # 1 Bit pro Status
        "size": CONFIG["status_list_size"]
    })


@app.route('/health', methods=['GET'])
def health():
    """Health Check."""
    return jsonify({"status": "ok", "issuer": CONFIG["issuer_name"]})


@app.route('/shortcode/<code>', methods=['GET'])
def resolve_shortcode(code: str):
    """
    Version 4.0: Short-Code zu voller Offer-URI auflösen.
    Ermöglicht einfache Eingabe einer 4-stelligen Zahl statt langer URLs.
    """
    if code in short_codes:
        offer_uri = short_codes[code]
        console.print(f"[cyan]...[/cyan] Short-Code {code} aufgelöst")
        return jsonify({
            "found": True,
            "offer_uri": offer_uri
        })
    else:
        return jsonify({
            "found": False,
            "error": f"Short-Code {code} nicht gefunden"
        }), 404


# ============================================================================
# Terminal Befehle
# ============================================================================

def create_offer(citizen_code: str):
    """Erstellt ein Credential Offer mit QR-Code und Short-Code (v4.0)."""
    if citizen_code not in citizen_db:
        console.print(f"[red]✗[/red] Bürger nicht gefunden: {citizen_code}")
        return
    
    citizen = citizen_db[citizen_code]
    
    # Pre-Authorized Code generieren
    pre_auth_code = secrets.token_urlsafe(24)
    pending_offers[pre_auth_code] = {
        "citizen_code": citizen_code,
        "created_at": datetime.utcnow().isoformat()
    }
    
    # Offer URI erstellen
    offer_uri = f"openid-credential-offer://?credential_issuer={CONFIG['issuer_uri']}&pre-authorized_code={pre_auth_code}"
    
    # Version 4.0: Short-Code generieren (4-stellig)
    short_code = str(secrets.randbelow(10000)).zfill(4)
    while short_code in short_codes:  # Kollisionen vermeiden
        short_code = str(secrets.randbelow(10000)).zfill(4)
    short_codes[short_code] = offer_uri
    
    console.print(Panel(
        f"[bold]Credential Offer für {citizen['given_name']} {citizen['family_name']}[/bold]\n\n"
        f"Pre-Authorized Code: [cyan]{pre_auth_code}[/cyan]\n"
        f"[bold yellow]Short-Code: {short_code}[/bold yellow]  ← Einfache Eingabe in Wallet\n"
        f"Gültig für: 5 Minuten",
        title="📋 Credential Offer",
        border_style="green"
    ))
    
    # QR-Code anzeigen
    try:
        qr = segno.make(offer_uri)
        console.print("\n[bold]QR-Code zum Scannen:[/bold]")
        qr.terminal(compact=True)
    except Exception:
        pass
    
    console.print(f"\n[dim]URI: {offer_uri}[/dim]")
    console.print(f"\n[yellow]Kopiere den Pre-Authorized Code ODER Short-Code '{short_code}' in die Wallet![/yellow]")
    
    # Version 5.0: File-Logging
    file_logger = get_issuer_logger()
    file_logger.log_offer_created(pre_auth_code, short_code, offer_uri)


def revoke_credential(index: int):
    """Widerruft ein Credential."""
    global status_list
    
    try:
        # Alten Status für Logging speichern
        old_status = 0
        try:
            old_status = 1 if sdjwt.get_status(status_list, index) else 0
        except:
            pass
        
        status_list = sdjwt.set_status(status_list, index, revoked=True)
        console.print(f"[green]\u2713[/green] Credential an Index {index} widerrufen")
        
        # Version 3.0: Crypto-Insight für Status Update
        if CONFIG.get("inspection_mode", False):
            crypto_insight.show_status_list_update(index, old_status, 1)
        
        # Version 5.0: File-Logging
        file_logger = get_issuer_logger()
        file_logger.log_status_list_update(index, old_status, 1)
    except IndexError as e:
        console.print(f"[red]✗[/red] {e}")


def show_citizens():
    """Zeigt alle Bürger in der Datenbank."""
    table = Table(title="Bürgerdatenbank", expand=False)
    table.add_column("Code", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Geburtsdatum", style="yellow")
    table.add_column("Status", style="magenta")
    
    for code, data in citizen_db.items():
        status_idx = issued_credentials.get(code)
        if status_idx is not None:
            try:
                is_revoked = sdjwt.get_status(status_list, status_idx)
                status = "[red]Widerrufen[/red]" if is_revoked else f"[green]Gültig (#{status_idx})[/green]"
            except:
                status = "[dim]Unbekannt[/dim]"
        else:
            status = "[dim]Nicht ausgestellt[/dim]"
        
        table.add_row(
            code,
            f"{data['given_name']} {data['family_name']}",
            data['birthdate'],
            status
        )
    
    console.print(table)


def show_help():
    """Zeigt Hilfe an."""
    help_text = """
[bold]Verfügbare Befehle:[/bold]

  [cyan]offer <code>[/cyan]     Erstellt ein Credential Offer für einen Bürger
                    Beispiel: offer 1234-CODE
  
  [cyan]list[/cyan]            Zeigt alle Bürger in der Datenbank
  
  [cyan]revoke <index>[/cyan]  Widerruft ein Credential anhand des Status-Index
                    Beispiel: revoke 0
  
  [cyan]status[/cyan]          Zeigt den Server-Status
  
  [cyan]help[/cyan]            Zeigt diese Hilfe
  
  [cyan]exit[/cyan]            Beendet den Server
"""
    console.print(Panel(help_text, title="Hilfe", border_style="blue"))


def command_loop():
    """Terminal-Befehlsschleife."""
    console.print("\n[bold green]Issuer bereit![/bold green] Tippe 'help' für Hilfe.\n")
    
    while True:
        try:
            cmd = Prompt.ask("[bold cyan]issuer>[/bold cyan]")
            parts = cmd.strip().split(maxsplit=1)
            
            if not parts:
                continue
            
            command = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else None
            
            if command == "offer":
                if arg:
                    create_offer(arg)
                else:
                    console.print("[red]Usage: offer <citizen_code>[/red]")
            
            elif command == "list":
                show_citizens()
            
            elif command == "revoke":
                if arg:
                    try:
                        revoke_credential(int(arg))
                    except ValueError:
                        console.print("[red]Index muss eine Zahl sein[/red]")
                else:
                    console.print("[red]Usage: revoke <index>[/red]")
            
            elif command == "status":
                console.print(f"[green]●[/green] Server läuft auf Port {CONFIG['port']}")
                console.print(f"[green]●[/green] {len(citizen_db)} Bürger in der Datenbank")
                console.print(f"[green]●[/green] {len(issued_credentials)} Credentials ausgestellt")
                console.print(f"[green]●[/green] {len(pending_offers)} offene Offers")
            
            elif command == "help":
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
                        # Zertifikat für Issuer erneuern
                        domain = CONFIG.get('issuer_uri', 'localhost').replace('https://', '').split(':')[0]
                        
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
            cert_path=CONFIG.get('ssl_cert', 'certs/issuer.crt'),
            key_path=CONFIG.get('ssl_key', 'certs/issuer.key')
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
        description="SD-JWT Issuer Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Beispiele:\n"
               "  python issuer.py                # Server normal starten\n"
               "  python issuer.py --renew-certs  # Nur Zertifikate erneuern\n"
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
    file_logger = get_issuer_logger()
    file_logger.logger.info(f"Issuer Server gestartet - {CONFIG['issuer_name']}")
    
    console.print(Panel(
        f"[bold]{CONFIG['issuer_name']}[/bold]\n"
        "SD-JWT Verifiable Credential Issuer\n"
        f"Version 6.0 - Port {CONFIG['port']}",
        title="\U0001f3db\ufe0f Issuer Server",
        border_style="blue"
    ))
    
    # Version 3.0: Inspection Mode Banner
    if CONFIG.get("inspection_mode", False):
        show_inspection_mode_banner()
        console.print("[dim]Deep-Trace Logging aktiv: logs/issuer_debug.log[/dim]\n")
    
    # Initialisierung
    load_or_create_keys()
    load_citizen_db()
    init_status_list()
    
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
    
    # Befehlsschleife starten
    command_loop()


if __name__ == "__main__":
    main()
