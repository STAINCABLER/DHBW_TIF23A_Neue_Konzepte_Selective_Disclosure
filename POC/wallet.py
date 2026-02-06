"""
SD-JWT Wallet
Terminal-basierte Wallet für Verifiable Credentials

Features:
- Key-Management (Ed25519)
- Credential Issuance (Pre-Authorized Code Flow)
- Selektive Disclosure bei Präsentation
- Persistente Speicherung in JSON
"""

import os
import sys
import json
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

import sd_jwt_utils as sdjwt
from log_manager import traffic_monitor, show_separator, show_inspection_mode_banner
from config_manager import ComponentConfig
from logger_config import get_wallet_logger

# SSL-Warnungen unterdrücken (nur für PoC!)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================================
# Konfiguration (wird beim Start geladen/erstellt)
# ============================================================================

CONFIG: Dict[str, Any] = {}

def load_config():
    """Lädt oder erstellt die Wallet-Konfiguration."""
    global CONFIG
    config_mgr = ComponentConfig("wallet")
    config = config_mgr.load_or_setup()
    
    CONFIG = {
        "wallet_store_path": config.get("wallet_store_path", "wallet_store.json"),
        "default_issuer": config.get("default_issuer", "https://localhost:5001"),
        "default_verifier": config.get("default_verifier", "https://localhost:5002"),
        "inspection_mode": config.get("inspection_mode", True)
    }

# ============================================================================
# Globale Variablen
# ============================================================================

console = Console()
wallet_data: Dict[str, Any] = {
    "keys": {},
    "credentials": []
}

# ============================================================================
# Wallet Storage
# ============================================================================

def load_wallet():
    """Lädt die Wallet aus der JSON-Datei."""
    global wallet_data
    
    store_path = CONFIG["wallet_store_path"]
    
    if os.path.exists(store_path):
        with open(store_path, 'r', encoding='utf-8') as f:
            wallet_data = json.load(f)
        console.print("[green]✓[/green] Wallet geladen")
        
        if wallet_data.get("keys", {}).get("private"):
            console.print(f"[green]✓[/green] Schlüsselpaar vorhanden")
        
        cred_count = len(wallet_data.get("credentials", []))
        if cred_count > 0:
            console.print(f"[green]✓[/green] {cred_count} Credential(s) gespeichert")
    else:
        wallet_data = {"keys": {}, "credentials": []}
        save_wallet()
        console.print("[yellow]![/yellow] Neue Wallet erstellt")


def save_wallet():
    """Speichert die Wallet in der JSON-Datei."""
    store_path = CONFIG["wallet_store_path"]
    
    with open(store_path, 'w', encoding='utf-8') as f:
        json.dump(wallet_data, f, indent=2, ensure_ascii=False)


def ensure_keys():
    """Stellt sicher, dass ein Schlüsselpaar existiert."""
    if not wallet_data.get("keys", {}).get("private"):
        console.print("[cyan]...[/cyan] Generiere neues Schlüsselpaar...")
        
        priv, pub = sdjwt.generate_ed25519_keypair()
        
        wallet_data["keys"] = {
            "private": sdjwt.key_to_base64(priv),
            "public": sdjwt.key_to_base64(pub)
        }
        
        save_wallet()
        console.print("[green]✓[/green] Neues Ed25519 Schlüsselpaar generiert")
        
        # Version 5.0: File-Logging
        file_logger = get_wallet_logger()
        file_logger.log_key_generation(wallet_data["keys"]["public"])
    else:
        # Version 5.0: Logging für geladene Keys
        file_logger = get_wallet_logger()
        file_logger.log_key_loaded(wallet_data["keys"]["public"])


def get_private_key() -> bytes:
    """Gibt den Private Key zurück."""
    return sdjwt.base64_to_key(wallet_data["keys"]["private"])


def get_public_key() -> bytes:
    """Gibt den Public Key zurück."""
    return sdjwt.base64_to_key(wallet_data["keys"]["public"])


# ============================================================================
# Issuance Flow
# ============================================================================

def receive_credential():
    """Empfängt ein neues Credential vom Issuer."""
    console.print(Panel(
        "[bold]Credential empfangen[/bold]\n\n"
        "Gib den Pre-Authorized Code ODER Short-Code (4 Ziffern) ein.",
        title="📥 Issuance",
        border_style="cyan"
    ))
    
    # Issuer URL eingeben
    issuer_url = Prompt.ask(
        "Issuer URL",
        default=CONFIG["default_issuer"]
    )
    issuer_url = issuer_url.rstrip('/')
    
    # Pre-Authorized Code oder Short-Code eingeben
    code_input = Prompt.ask("Pre-Authorized Code oder Short-Code (4 Ziffern)")
    
    if not code_input:
        console.print("[red]✗[/red] Kein Code eingegeben")
        return
    
    pre_auth_code = code_input
    
    # Version 4.0: Prüfe ob Short-Code (4-stellig, nur Ziffern)
    if len(code_input) == 4 and code_input.isdigit():
        console.print(f"[cyan]...[/cyan] Short-Code erkannt, löse auf...")
        try:
            shortcode_response = requests.get(
                f"{issuer_url}/shortcode/{code_input}",
                verify=False,
                timeout=5
            )
            if shortcode_response.status_code == 200:
                data = shortcode_response.json()
                if data.get("found"):
                    # Extrahiere Pre-Auth-Code aus Offer URI
                    offer_uri = data.get("offer_uri", "")
                    if "pre-authorized_code=" in offer_uri:
                        pre_auth_code = offer_uri.split("pre-authorized_code=")[1].split("&")[0]
                        console.print(f"[green]✓[/green] Short-Code aufgelöst")
                    else:
                        console.print(f"[red]✗[/red] Ungültiges Offer-Format")
                        return
                else:
                    console.print(f"[red]✗[/red] Short-Code nicht gefunden")
                    return
            else:
                console.print(f"[yellow]![/yellow] Short-Code nicht gefunden, verwende als Pre-Auth-Code")
        except Exception as e:
            console.print(f"[yellow]![/yellow] Short-Code Auflösung fehlgeschlagen: {e}")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        # Schritt 1: Token anfordern
        task = progress.add_task("Fordere Access Token an...", total=None)
        
        try:
            token_response = requests.post(
                f"{issuer_url}/token",
                json={
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code": pre_auth_code
                },
                verify=False,
                timeout=10
            )
            
            if token_response.status_code != 200:
                error = token_response.json().get("error", "Unknown error")
                console.print(f"[red]✗[/red] Token-Fehler: {error}")
                return
            
            token_data = token_response.json()
            access_token = token_data["access_token"]
            c_nonce = token_data.get("c_nonce", "")
            
            progress.update(task, description="[green]✓[/green] Access Token erhalten")
            
            # Version 3.0: Traffic Monitor
            if CONFIG.get("inspection_mode", False):
                traffic_monitor.show_outgoing_request(
                    "POST", f"{issuer_url}/token",
                    {"grant_type": "pre-authorized_code", "pre-authorized_code": pre_auth_code[:20] + "..."}
                )
                traffic_monitor.show_incoming_response(token_response.status_code, {
                    "access_token": access_token[:20] + "...",
                    "c_nonce": c_nonce[:20] + "..." if c_nonce else ""
                })
            
        except requests.exceptions.RequestException as e:
            console.print(f"[red]✗[/red] Verbindungsfehler: {e}")
            return
        
        # Schritt 2: Proof of Possession erstellen
        progress.update(task, description="Erstelle Proof of Possession...")
        
        private_key = sdjwt.load_private_key(get_private_key())
        public_key = get_public_key()
        
        # Proof JWT erstellen
        proof_header = {
            "alg": "EdDSA",
            "typ": "openid4vci-proof+jwt",
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": sdjwt.key_to_base64(public_key)
            }
        }
        
        proof_payload = {
            "iss": "wallet",
            "aud": issuer_url,
            "iat": int(datetime.utcnow().timestamp()),
            "nonce": c_nonce
        }
        
        # Manuell signieren (da Header-Format speziell)
        header_b64 = sdjwt.encode_jwt_part(proof_header)
        payload_b64 = sdjwt.encode_jwt_part(proof_payload)
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        signature = private_key.sign(signing_input)
        signature_b64 = sdjwt.base64url_encode(signature)
        proof_jwt = f"{header_b64}.{payload_b64}.{signature_b64}"
        
        progress.update(task, description="[green]✓[/green] Proof erstellt")
        
        # Schritt 3: Credential anfordern
        progress.update(task, description="Fordere Credential an...")
        
        try:
            cred_response = requests.post(
                f"{issuer_url}/credential",
                headers={"Authorization": f"Bearer {access_token}"},
                json={
                    "format": "sd_jwt_vc",
                    "proof": {
                        "proof_type": "jwt",
                        "jwt": proof_jwt
                    }
                },
                verify=False,
                timeout=10
            )
            
            if cred_response.status_code != 200:
                error = cred_response.json().get("error", "Unknown error")
                console.print(f"[red]✗[/red] Credential-Fehler: {error}")
                return
            
            cred_data = cred_response.json()
            
            progress.update(task, description="[green]✓[/green] Credential empfangen")
            
            # Version 3.0: Traffic Monitor
            if CONFIG.get("inspection_mode", False):
                traffic_monitor.show_incoming_response(cred_response.status_code, {
                    "format": cred_data.get("format"),
                    "credential": cred_data.get("credential", "")[:50] + "...",
                    "disclosures": f"{len(cred_data.get('disclosures', []))} Disclosures"
                })
            
        except requests.exceptions.RequestException as e:
            console.print(f"[red]✗[/red] Verbindungsfehler: {e}")
            return
    
    # Credential speichern
    sd_jwt = cred_data["credential"]
    disclosures = cred_data["disclosures"]
    disclosure_mapping = cred_data.get("disclosure_mapping", {})
    
    # Credential parsen für Anzeige
    payload = sdjwt.get_jwt_payload(sd_jwt)
    
    credential_entry = {
        "id": len(wallet_data["credentials"]) + 1,
        "issuer": payload.get("iss", issuer_url),
        "issued_at": datetime.utcnow().isoformat(),
        "expires_at": datetime.fromtimestamp(payload.get("exp", 0)).isoformat(),
        "sd_jwt": sd_jwt,
        "disclosures": disclosures,
        "disclosure_mapping": disclosure_mapping
    }
    
    wallet_data["credentials"].append(credential_entry)
    save_wallet()
    
    # Version 5.0: File-Logging
    file_logger = get_wallet_logger()
    file_logger.log_credential_received(
        issuer=credential_entry["issuer"],
        sd_jwt_preview=sd_jwt[:80],
        disclosures_count=len(disclosures)
    )
    file_logger.log_credential_stored(
        credential_id=credential_entry.get("subject", "unknown"),
        claims=list(disclosure_mapping.keys())
    )
    
    # Version 3.0: Traffic Monitor - Credential Storage
    if CONFIG.get("inspection_mode", False):
        traffic_monitor.show_credential_storage({
            "sd_jwt": sd_jwt,
            "disclosures": disclosures,
            "issuer": credential_entry["issuer"]
        })
    
    # Erfolgsanzeige
    console.print(Panel(
        "[bold green]Credential erfolgreich gespeichert![/bold green]",
        border_style="green"
    ))
    
    # Claims anzeigen
    table = Table(title="Enthaltene Claims", expand=False)
    table.add_column("Claim", style="cyan")
    table.add_column("Wert", style="green")
    
    for claim_name, disclosure in disclosure_mapping.items():
        try:
            _, _, value = sdjwt.decode_disclosure(disclosure)
            table.add_row(claim_name, str(value))
        except:
            table.add_row(claim_name, "[dim]Fehler[/dim]")
    
    console.print(table)


# ============================================================================
# Presentation Flow
# ============================================================================

def present_credential():
    """Präsentiert ein Credential an einen Verifier."""
    credentials = wallet_data.get("credentials", [])
    
    if not credentials:
        console.print("[yellow]Keine Credentials in der Wallet[/yellow]")
        return
    
    console.print(Panel(
        "[bold]Credential präsentieren[/bold]\n\n"
        "Wähle ein Credential aus und entscheide, welche Daten du teilen möchtest.",
        title="📤 Präsentation",
        border_style="magenta"
    ))
    
    # Credential auswählen wenn mehrere vorhanden
    if len(credentials) > 1:
        console.print("\n[bold]Verfügbare Credentials:[/bold]")
        for i, cred in enumerate(credentials, 1):
            console.print(f"  [{i}] {cred['issuer']} - {cred['issued_at'][:10]}")
        
        choice = Prompt.ask("Credential Nr.", default="1")
        try:
            cred_index = int(choice) - 1
            if cred_index < 0 or cred_index >= len(credentials):
                raise ValueError()
        except ValueError:
            console.print("[red]Ungültige Auswahl[/red]")
            return
    else:
        cred_index = 0
    
    credential = credentials[cred_index]
    disclosure_mapping = credential.get("disclosure_mapping", {})
    
    # Verifier URL/Short-Code eingeben
    console.print("\n[bold]Verifier auswählen:[/bold]")
    console.print("[dim]Gib die Verifier URL ODER einen Short-Code (4 Ziffern) ein.[/dim]")
    
    verifier_input = Prompt.ask(
        "Verifier URL oder Short-Code",
        default=CONFIG["default_verifier"]
    )
    
    verifier_url = verifier_input.rstrip('/')
    nonce = None
    audience = None
    
    # Version 4.0: Short-Code Auflösung
    if len(verifier_input) == 4 and verifier_input.isdigit():
        console.print(f"[cyan]...[/cyan] Short-Code erkannt, löse auf...")
        # Versuche bei default Verifier
        shortcode_url = CONFIG["default_verifier"]
        try:
            shortcode_response = requests.get(
                f"{shortcode_url}/shortcode/{verifier_input}",
                verify=False,
                timeout=5
            )
            if shortcode_response.status_code == 200:
                data = shortcode_response.json()
                if data.get("found"):
                    nonce = data.get("nonce")
                    audience = data.get("verifier_uri", shortcode_url)
                    verifier_url = shortcode_url
                    console.print(f"[green]✓[/green] Short-Code aufgelöst")
                    console.print(f"[dim]  Verifier: {verifier_url}[/dim]")
                else:
                    console.print(f"[red]✗[/red] Short-Code nicht gefunden")
                    return
            else:
                console.print(f"[red]✗[/red] Short-Code nicht gefunden")
                return
        except Exception as e:
            console.print(f"[red]✗[/red] Short-Code Auflösung fehlgeschlagen: {e}")
            return
    
    # Challenge vom Verifier holen (nur wenn nicht per Short-Code erhalten)
    if nonce is None:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task = progress.add_task("Hole Challenge vom Verifier...", total=None)
            
            try:
                challenge_response = requests.get(
                    f"{verifier_url}/challenge",
                    verify=False,
                    timeout=10
                )
                
                if challenge_response.status_code != 200:
                    console.print("[red]✗[/red] Konnte Challenge nicht abrufen")
                    return
                
                challenge_data = challenge_response.json()
                nonce = challenge_data["nonce"]
                audience = challenge_data.get("audience", verifier_url)
                
                progress.update(task, description="[green]✓[/green] Challenge erhalten")
                
            except requests.exceptions.RequestException as e:
                console.print(f"[red]✗[/red] Verbindungsfehler: {e}")
            return
    
    # Claims zur Auswahl anzeigen
    console.print("\n[bold]Wähle die Claims aus, die du teilen möchtest:[/bold]")
    console.print("[dim](Trenne mehrere mit Komma, z.B.: 1,2,4)[/dim]\n")
    
    claim_names = list(disclosure_mapping.keys())
    
    for i, claim_name in enumerate(claim_names, 1):
        try:
            disclosure = disclosure_mapping[claim_name]
            _, _, value = sdjwt.decode_disclosure(disclosure)
            console.print(f"  [cyan][{i}][/cyan] {claim_name}: [green]{value}[/green]")
        except:
            console.print(f"  [cyan][{i}][/cyan] {claim_name}: [dim]Fehler[/dim]")
    
    console.print(f"  [cyan][A][/cyan] Alle auswählen")
    
    selection = Prompt.ask("\nAuswahl", default="A")
    
    # Selection parsen
    if selection.upper() == "A":
        selected_indices = list(range(len(claim_names)))
    else:
        try:
            selected_indices = [int(s.strip()) - 1 for s in selection.split(",")]
            # Validieren
            for idx in selected_indices:
                if idx < 0 or idx >= len(claim_names):
                    raise ValueError()
        except ValueError:
            console.print("[red]Ungültige Auswahl[/red]")
            return
    
    # Ausgewählte Disclosures sammeln
    selected_disclosures = []
    selected_claims = []
    
    for idx in selected_indices:
        claim_name = claim_names[idx]
        disclosure = disclosure_mapping[claim_name]
        selected_disclosures.append(disclosure)
        selected_claims.append(claim_name)
    
    console.print(f"\n[green]✓[/green] {len(selected_disclosures)} Claim(s) ausgewählt: {', '.join(selected_claims)}")
    
    # Version 5.0: File-Logging für Disclosure Selection
    file_logger = get_wallet_logger()
    file_logger.log_disclosure_selection(claim_names, selected_claims)
    
    # Version 3.0: Traffic Monitor - Privacy Decision
    if CONFIG.get("inspection_mode", False):
        show_separator("PRIVACY DECISION")
        traffic_monitor.show_disclosure_selection(claim_names, selected_claims)
    
    # Version 4.0: Consent Screen mit klarer Warnung
    not_shared = [c for c in claim_names if c not in selected_claims]
    
    consent_text = f"[bold]ACHTUNG: Datenfreigabe[/bold]\n\n"
    consent_text += f"[cyan]Verifier:[/cyan] {verifier_url}\n\n"
    consent_text += f"[green]✓ WIRD GETEILT:[/green]\n"
    for claim in selected_claims:
        try:
            disclosure = disclosure_mapping[claim]
            _, _, value = sdjwt.decode_disclosure(disclosure)
            consent_text += f"   • {claim}: {value}\n"
        except:
            consent_text += f"   • {claim}\n"
    
    if not_shared:
        consent_text += f"\n[red]✗ WIRD NICHT GETEILT:[/red]\n"
        for claim in not_shared:
            consent_text += f"   • {claim}\n"
    
    console.print(Panel(
        consent_text,
        title="⚠️ Consent / Zustimmung",
        border_style="yellow"
    ))
    
    # Bestätigung
    if not Confirm.ask("[bold]Daten wirklich an diesen Verifier senden?[/bold]", default=False):
        console.print("[yellow]Abgebrochen - Keine Daten wurden gesendet.[/yellow]")
        return
    
    # Key Binding JWT erstellen
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        task = progress.add_task("Erstelle Key Binding JWT...", total=None)
        
        private_key = sdjwt.load_private_key(get_private_key())
        
        kb_jwt = sdjwt.create_kb_jwt(
            sd_jwt=credential["sd_jwt"],
            holder_private_key=private_key,
            audience=audience,
            nonce=nonce
        )
        
        progress.update(task, description="[green]✓[/green] KB-JWT erstellt")
        
        # Version 3.0: Traffic Monitor - KB-JWT Creation
        if CONFIG.get("inspection_mode", False):
            import hashlib
            sd_hash = sdjwt.base64url_encode(
                hashlib.sha256(credential["sd_jwt"].encode('ascii')).digest()
            )
            traffic_monitor.show_kb_jwt_creation(nonce, audience, sd_hash)
        
        # Präsentation erstellen
        progress.update(task, description="Sende Präsentation...")
        
        # Presentation im String-Format: SD-JWT~Disclosure1~...~KB-JWT
        presentation = sdjwt.create_presentation(
            credential["sd_jwt"],
            selected_disclosures,
            kb_jwt
        )
        
        # Version 3.0: Traffic Monitor - Outgoing Presentation
        if CONFIG.get("inspection_mode", False):
            traffic_monitor.show_presentation_packet(
                credential["sd_jwt"],
                len(selected_disclosures),
                kb_jwt
            )
        
        # Version 5.0: File-Logging
        file_logger = get_wallet_logger()
        file_logger.log_presentation_sent(verifier_url, len(selected_disclosures))
        
        try:
            verify_response = requests.post(
                f"{verifier_url}/verify",
                json={
                    "presentation": presentation
                },
                verify=False,
                timeout=10
            )
            
            result = verify_response.json()
            
            progress.update(task, description="[green]✓[/green] Antwort erhalten")
            
        except requests.exceptions.RequestException as e:
            console.print(f"[red]✗[/red] Verbindungsfehler: {e}")
            return
    
    # Ergebnis anzeigen
    if result.get("valid"):
        console.print(Panel(
            "[bold green]✓ Verifizierung erfolgreich![/bold green]\n\n"
            "Der Verifier hat dein Credential akzeptiert.",
            border_style="green"
        ))
    else:
        error = result.get("error", "Unbekannter Fehler")
        console.print(Panel(
            f"[bold red]✗ Verifizierung fehlgeschlagen[/bold red]\n\n"
            f"Fehler: {error}",
            border_style="red"
        ))


# ============================================================================
# Wallet Verwaltung
# ============================================================================

def show_credentials():
    """Zeigt alle gespeicherten Credentials an."""
    credentials = wallet_data.get("credentials", [])
    
    if not credentials:
        console.print("[yellow]Keine Credentials in der Wallet[/yellow]")
        return
    
    for i, cred in enumerate(credentials, 1):
        disclosure_mapping = cred.get("disclosure_mapping", {})
        
        console.print(Panel(
            f"[bold]Credential #{i}[/bold]",
            border_style="blue"
        ))
        
        table = Table(expand=False)
        table.add_column("Eigenschaft", style="cyan")
        table.add_column("Wert", style="green")
        
        table.add_row("Issuer", cred.get("issuer", "Unbekannt"))
        table.add_row("Ausgestellt", cred.get("issued_at", "")[:19])
        table.add_row("Gültig bis", cred.get("expires_at", "")[:19])
        
        console.print(table)
        
        # Claims anzeigen
        if disclosure_mapping:
            claims_table = Table(title="Gespeicherte Claims", expand=False)
            claims_table.add_column("Claim", style="cyan")
            claims_table.add_column("Wert", style="green")
            
            for claim_name, disclosure in disclosure_mapping.items():
                try:
                    _, _, value = sdjwt.decode_disclosure(disclosure)
                    claims_table.add_row(claim_name, str(value))
                except:
                    claims_table.add_row(claim_name, "[dim]Fehler[/dim]")
            
            console.print(claims_table)
        
        console.print("")


def delete_credential():
    """Löscht ein Credential."""
    credentials = wallet_data.get("credentials", [])
    
    if not credentials:
        console.print("[yellow]Keine Credentials zum Löschen[/yellow]")
        return
    
    console.print("\n[bold]Credentials:[/bold]")
    for i, cred in enumerate(credentials, 1):
        console.print(f"  [{i}] {cred['issuer']} - {cred['issued_at'][:10]}")
    
    choice = Prompt.ask("Welches Credential löschen?")
    
    try:
        cred_index = int(choice) - 1
        if cred_index < 0 or cred_index >= len(credentials):
            raise ValueError()
    except ValueError:
        console.print("[red]Ungültige Auswahl[/red]")
        return
    
    if Confirm.ask("Wirklich löschen?", default=False):
        del wallet_data["credentials"][cred_index]
        save_wallet()
        console.print("[green]✓[/green] Credential gelöscht")


def show_keys():
    """Zeigt die Wallet-Keys an."""
    keys = wallet_data.get("keys", {})
    
    if not keys.get("public"):
        console.print("[yellow]Keine Keys vorhanden[/yellow]")
        return
    
    table = Table(title="Wallet Keys", expand=False)
    table.add_column("Typ", style="cyan")
    table.add_column("Wert (gekürzt)", style="green")
    
    table.add_row("Public Key", keys["public"][:40] + "...")
    table.add_row("Private Key", "[dim]●●●●●●●●●● (geschützt)[/dim]")
    
    console.print(table)


def show_help():
    """Zeigt die Hilfe an."""
    help_text = """
[bold]Verfügbare Befehle:[/bold]

  [cyan]receive[/cyan]     Empfange ein neues Credential vom Issuer
              (benötigt Pre-Authorized Code)
  
  [cyan]present[/cyan]     Präsentiere ein Credential an einen Verifier
              (wähle selektiv welche Daten geteilt werden)
  
  [cyan]list[/cyan]        Zeige alle gespeicherten Credentials
  
  [cyan]delete[/cyan]      Lösche ein Credential
  
  [cyan]keys[/cyan]        Zeige Wallet-Schlüssel
  
  [cyan]help[/cyan]        Zeige diese Hilfe
  
  [cyan]exit[/cyan]        Beende die Wallet
"""
    console.print(Panel(help_text, title="Hilfe", border_style="blue"))


# ============================================================================
# Main
# ============================================================================

def main():
    """Hauptfunktion."""
    # Konfiguration laden (First-Run Setup falls nötig)
    load_config()
    
    # Version 5.0: File-Logger initialisieren
    file_logger = get_wallet_logger()
    file_logger.logger.info("Wallet gestartet")
    
    console.print(Panel(
        "[bold]SD-JWT Wallet[/bold]\n"
        "Deine digitale Brieftasche für Verifiable Credentials\n"
        "Version 6.0",
        title="👛 Wallet",
        border_style="magenta"
    ))
    
    # Version 3.0: Inspection Mode Banner
    if CONFIG.get("inspection_mode", False):
        show_inspection_mode_banner()
        console.print("[dim]Deep-Trace Logging aktiv: logs/wallet_debug.log[/dim]\n")
    
    # Initialisierung
    load_wallet()
    ensure_keys()
    
    console.print("\n[bold green]Wallet bereit![/bold green] Tippe 'help' für Hilfe.\n")
    
    # Hauptschleife
    while True:
        try:
            cmd = Prompt.ask("[bold magenta]wallet>[/bold magenta]")
            command = cmd.strip().lower()
            
            if not command:
                continue
            
            if command in ["receive", "r", "get"]:
                receive_credential()
            
            elif command in ["present", "p", "send", "show"]:
                present_credential()
            
            elif command in ["list", "l", "credentials", "creds"]:
                show_credentials()
            
            elif command in ["delete", "del", "remove"]:
                delete_credential()
            
            elif command in ["keys", "k"]:
                show_keys()
            
            elif command in ["help", "h", "?"]:
                show_help()
            
            elif command in ["exit", "quit", "q"]:
                console.print("[yellow]Wallet wird geschlossen...[/yellow]")
                break
            
            else:
                console.print(f"[red]Unbekannter Befehl: {command}[/red]")
                console.print("[dim]Tippe 'help' für Hilfe[/dim]")
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Wallet wird geschlossen...[/yellow]")
            break
        except Exception as e:
            console.print(f"[red]Fehler: {e}[/red]")


if __name__ == "__main__":
    main()
