"""
Log Manager - Live-Inspection Module für SD-JWT PoC
Version 3.0: Observability für Präsentationen

Dieses Modul macht die "Black Box" transparent:
- Crypto-Insight: Zeigt Hashing, Salting, Signatur-Operationen
- Traffic-Monitor: Zeigt HTTP-Requests/Responses
- Verification-Logic: Zeigt Prüfschritte als Checkliste
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.text import Text
from rich.columns import Columns
from rich import box
import json
from typing import Any, Dict, List, Optional

console = Console()


# ============================================================================
# Farb-Schema für verschiedene Log-Typen
# ============================================================================

COLORS = {
    "crypto": "cyan",       # Kryptografische Operationen
    "traffic": "yellow",    # Netzwerk-Traffic
    "verify": "green",      # Verifikations-Schritte
    "error": "red",         # Fehler
    "data": "blue",         # Daten-Transformationen
    "privacy": "magenta",   # Privacy-relevante Infos
}


# ============================================================================
# Crypto Insight (für Issuer)
# ============================================================================

class CryptoInsight:
    """Visualisiert kryptografische Operationen beim Issuer."""
    
    @staticmethod
    def show_raw_data(citizen_code: str, data: Dict[str, Any]):
        """Zeigt die Rohdaten aus der Datenbank."""
        table = Table(
            title=f"📋 Rohdaten für [{citizen_code}]",
            box=box.ROUNDED,
            border_style=COLORS["data"]
        )
        table.add_column("Feld", style="cyan")
        table.add_column("Wert", style="white")
        
        for key, value in data.items():
            table.add_row(key, str(value))
        
        console.print(Panel(
            table,
            title="[bold blue]SCHRITT 1: RAW DATA[/bold blue]",
            border_style=COLORS["data"],
            subtitle="Daten aus citizen_db.json"
        ))
    
    @staticmethod
    def show_salting(claim_name: str, claim_value: Any, salt: str, disclosure_array: List):
        """Zeigt den Salting-Prozess für einen Claim."""
        content = Text()
        content.append("Claim: ", style="dim")
        content.append(f"{claim_name}\n", style="cyan bold")
        content.append("Wert: ", style="dim")
        content.append(f"{claim_value}\n", style="green")
        content.append("Salt: ", style="dim")
        content.append(f"{salt[:20]}...\n", style="yellow")
        content.append("\nDisclosure Array:\n", style="dim")
        content.append(f'["{salt[:12]}...", "{claim_name}", "{claim_value}"]', style="white")
        
        console.print(Panel(
            content,
            title=f"[bold cyan]SCHRITT 2: SALTING - {claim_name}[/bold cyan]",
            border_style=COLORS["crypto"]
        ))
    
    @staticmethod
    def show_hashing(claim_name: str, disclosure_b64: str, hash_digest: str):
        """Zeigt den Hashing-Prozess."""
        content = Text()
        content.append("Disclosure (Base64):\n", style="dim")
        content.append(f"{disclosure_b64[:50]}...\n\n", style="white")
        content.append("SHA-256 Hash:\n", style="dim")
        content.append(f"{hash_digest}", style="green bold")
        
        console.print(Panel(
            content,
            title=f"[bold cyan]SCHRITT 3: HASHING - {claim_name}[/bold cyan]",
            border_style=COLORS["crypto"],
            subtitle="SHA-256 → Base64URL"
        ))
    
    @staticmethod
    def show_token_structure(payload: Dict, disclosures_count: int):
        """Zeigt die finale Token-Struktur."""
        # Payload als formatiertes JSON
        payload_json = json.dumps(payload, indent=2, ensure_ascii=False)
        
        content = Text()
        content.append("SD-JWT Payload (Hashes statt Klartext):\n\n", style="dim")
        
        console.print(Panel(
            Syntax(payload_json, "json", theme="monokai", line_numbers=False),
            title="[bold cyan]SCHRITT 4: TOKEN-BAU[/bold cyan]",
            border_style=COLORS["crypto"],
            subtitle=f"_sd Array enthält {disclosures_count} Hashes"
        ))
    
    @staticmethod
    def show_signature(algorithm: str, key_id: str):
        """Zeigt die Signatur-Operation."""
        content = Text()
        content.append("Algorithmus: ", style="dim")
        content.append(f"{algorithm}\n", style="cyan bold")
        content.append("Key: ", style="dim")
        content.append(f"{key_id[:30]}...\n", style="yellow")
        content.append("\n✓ ", style="green bold")
        content.append("Signatur erstellt", style="green")
        
        console.print(Panel(
            content,
            title="[bold cyan]SCHRITT 5: SIGNATUR[/bold cyan]",
            border_style=COLORS["crypto"]
        ))
    
    @staticmethod
    def show_status_list_update(index: int, old_value: int, new_value: int):
        """Zeigt eine Änderung in der Status-Liste."""
        content = Text()
        content.append("Index: ", style="dim")
        content.append(f"{index}\n", style="cyan bold")
        content.append("Alter Wert: ", style="dim")
        content.append(f"{old_value} ", style="green" if old_value == 0 else "red")
        content.append("(Gültig)" if old_value == 0 else "(Widerrufen)", style="dim")
        content.append("\nNeuer Wert: ", style="dim")
        content.append(f"{new_value} ", style="green" if new_value == 0 else "red")
        content.append("(Gültig)" if new_value == 0 else "(Widerrufen)", style="dim")
        
        console.print(Panel(
            content,
            title="[bold red]STATUS LIST UPDATE[/bold red]",
            border_style=COLORS["error"] if new_value == 1 else COLORS["verify"]
        ))


# ============================================================================
# Traffic Monitor (für Wallet)
# ============================================================================

class TrafficMonitor:
    """Visualisiert HTTP-Traffic bei der Wallet."""
    
    @staticmethod
    def show_outgoing_request(method: str, url: str, body: Optional[Dict] = None):
        """Zeigt einen ausgehenden HTTP-Request."""
        content = Text()
        content.append(f"{method} ", style="cyan bold")
        content.append(f"{url}\n", style="white")
        
        if body:
            content.append("\nBody:\n", style="dim")
        
        panel_content = content
        
        if body:
            body_json = json.dumps(body, indent=2, ensure_ascii=False)
            # Sensible Daten kürzen
            if len(body_json) > 500:
                body_json = body_json[:500] + "\n... (gekürzt)"
            panel_content = Columns([
                content,
                Syntax(body_json, "json", theme="monokai", line_numbers=False)
            ])
        
        console.print(Panel(
            panel_content if not body else Syntax(
                f"{method} {url}\n\n{json.dumps(body, indent=2, ensure_ascii=False)[:500]}",
                "http",
                theme="monokai"
            ),
            title="[bold yellow]⬆ OUTGOING REQUEST[/bold yellow]",
            border_style=COLORS["traffic"]
        ))
    
    @staticmethod
    def show_incoming_response(status_code: int, body: Optional[Dict] = None):
        """Zeigt eine eingehende HTTP-Response."""
        status_color = "green" if status_code < 400 else "red"
        
        content = Text()
        content.append("Status: ", style="dim")
        content.append(f"{status_code}\n", style=f"{status_color} bold")
        
        if body:
            body_json = json.dumps(body, indent=2, ensure_ascii=False)
            if len(body_json) > 500:
                body_json = body_json[:500] + "\n... (gekürzt)"
            
            console.print(Panel(
                Syntax(body_json, "json", theme="monokai", line_numbers=False),
                title=f"[bold yellow]⬇ INCOMING RESPONSE ({status_code})[/bold yellow]",
                border_style=COLORS["traffic"]
            ))
        else:
            console.print(Panel(
                content,
                title="[bold yellow]⬇ INCOMING RESPONSE[/bold yellow]",
                border_style=COLORS["traffic"]
            ))
    
    @staticmethod
    def show_credential_storage(credential_summary: Dict):
        """Zeigt wie ein Credential gespeichert wird."""
        content = Text()
        content.append("Speichere in wallet_store.json:\n\n", style="dim")
        content.append("SD-JWT: ", style="cyan")
        content.append(f"{credential_summary.get('sd_jwt', '')[:40]}...\n", style="white")
        content.append("Disclosures: ", style="cyan")
        content.append(f"{len(credential_summary.get('disclosures', []))} Stück\n", style="white")
        content.append("Issuer: ", style="cyan")
        content.append(f"{credential_summary.get('issuer', 'Unknown')}\n", style="white")
        
        console.print(Panel(
            content,
            title="[bold blue]💾 CREDENTIAL STORAGE[/bold blue]",
            border_style=COLORS["data"]
        ))
    
    @staticmethod
    def show_disclosure_selection(all_claims: List[str], selected_claims: List[str]):
        """Zeigt welche Disclosures gesendet werden und welche nicht."""
        table = Table(
            title="Selektive Offenlegung",
            box=box.ROUNDED,
            border_style=COLORS["privacy"]
        )
        table.add_column("Claim", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Aktion", style="dim")
        
        for claim in all_claims:
            if claim in selected_claims:
                table.add_row(
                    claim,
                    "[green]✓ GESENDET[/green]",
                    "Disclosure wird übertragen"
                )
            else:
                table.add_row(
                    claim,
                    "[red]✗ ZURÜCKGEHALTEN[/red]",
                    "Bleibt in der Wallet"
                )
        
        console.print(Panel(
            table,
            title="[bold magenta]🔒 PRIVACY DECISION[/bold magenta]",
            border_style=COLORS["privacy"],
            subtitle="Nur ausgewählte Daten werden geteilt"
        ))
    
    @staticmethod
    def show_kb_jwt_creation(nonce: str, audience: str, sd_hash: str):
        """Zeigt die Erstellung des Key Binding JWT."""
        content = Text()
        content.append("Key Binding JWT erstellen:\n\n", style="dim")
        content.append("Nonce (vom Verifier): ", style="cyan")
        content.append(f"{nonce[:30]}...\n", style="white")
        content.append("Audience: ", style="cyan")
        content.append(f"{audience}\n", style="white")
        content.append("SD-JWT Hash: ", style="cyan")
        content.append(f"{sd_hash[:30]}...\n\n", style="white")
        content.append("✓ ", style="green bold")
        content.append("Signiert mit Wallet Private Key", style="green")
        
        console.print(Panel(
            content,
            title="[bold cyan]🔑 KEY BINDING JWT[/bold cyan]",
            border_style=COLORS["crypto"],
            subtitle="Besitznachweis durch Signatur"
        ))
    
    @staticmethod
    def show_presentation_packet(sd_jwt: str, disclosure_count: int, kb_jwt: str):
        """Zeigt das finale Präsentations-Paket."""
        content = Text()
        content.append("Präsentations-String:\n\n", style="dim")
        content.append("<SD-JWT>", style="cyan bold")
        content.append(" ~ ", style="yellow")
        content.append(f"<{disclosure_count} Disclosure(s)>", style="green bold")
        content.append(" ~ ", style="yellow")
        content.append("<KB-JWT>", style="magenta bold")
        content.append("\n\n", style="dim")
        content.append(f"{sd_jwt[:30]}...~...~{kb_jwt[-30:]}", style="dim white")
        
        console.print(Panel(
            content,
            title="[bold yellow]📤 OUTGOING PRESENTATION[/bold yellow]",
            border_style=COLORS["traffic"]
        ))


# ============================================================================
# Verification Logic (für Verifier)
# ============================================================================

class VerificationLogic:
    """Visualisiert den Verifikations-Prozess beim Verifier."""
    
    def __init__(self):
        self.checks: List[Dict] = []
    
    def add_check(self, name: str, passed: bool, details: str = ""):
        """Fügt einen Prüfschritt hinzu."""
        self.checks.append({
            "name": name,
            "passed": passed,
            "details": details
        })
    
    def show_incoming_presentation(self, sd_jwt: str, disclosures: List[str], kb_jwt: str):
        """Zeigt die empfangene Präsentation."""
        content = Text()
        content.append("Empfangene Teile:\n\n", style="dim")
        content.append("1. SD-JWT: ", style="cyan")
        content.append(f"{sd_jwt[:50]}...\n", style="white")
        content.append("2. Disclosures: ", style="cyan")
        content.append(f"{len(disclosures)} Stück\n", style="white")
        content.append("3. KB-JWT: ", style="cyan")
        content.append(f"{kb_jwt[:50]}...\n", style="white")
        
        console.print(Panel(
            content,
            title="[bold yellow]📥 INCOMING PRESENTATION[/bold yellow]",
            border_style=COLORS["traffic"]
        ))
    
    def show_hash_verification(self, claim_name: str, disclosure: str, 
                               computed_hash: str, found_in_sd: bool):
        """Zeigt die Hash-Verifikation für eine Disclosure."""
        content = Text()
        content.append("Disclosure: ", style="dim")
        content.append(f"{disclosure[:40]}...\n", style="white")
        content.append("Berechneter Hash: ", style="dim")
        content.append(f"{computed_hash[:40]}...\n", style="cyan")
        content.append("Im _sd Array: ", style="dim")
        
        if found_in_sd:
            content.append("✓ GEFUNDEN", style="green bold")
        else:
            content.append("✗ NICHT GEFUNDEN", style="red bold")
        
        console.print(Panel(
            content,
            title=f"[bold cyan]HASH-CHECK: {claim_name}[/bold cyan]",
            border_style=COLORS["verify"] if found_in_sd else COLORS["error"]
        ))
    
    def show_status_check(self, index: int, uri: str, bit_value: int):
        """Zeigt die Status-List-Prüfung."""
        is_valid = bit_value == 0
        
        content = Text()
        content.append("Status List URI: ", style="dim")
        content.append(f"{uri}\n", style="white")
        content.append("Index: ", style="dim")
        content.append(f"{index}\n", style="cyan")
        content.append("Bit-Wert: ", style="dim")
        content.append(f"{bit_value} ", style="green bold" if is_valid else "red bold")
        content.append("(GÜLTIG)" if is_valid else "(WIDERRUFEN)", 
                      style="green" if is_valid else "red")
        
        console.print(Panel(
            content,
            title="[bold blue]📋 STATUS LIST CHECK[/bold blue]",
            border_style=COLORS["verify"] if is_valid else COLORS["error"]
        ))
    
    def show_checklist(self):
        """Zeigt die finale Checkliste aller Prüfungen."""
        table = Table(
            title="Verifikations-Checkliste",
            box=box.ROUNDED,
            border_style=COLORS["verify"]
        )
        table.add_column("Prüfung", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Details", style="dim")
        
        all_passed = True
        for check in self.checks:
            status = "[green]✓ PASS[/green]" if check["passed"] else "[red]✗ FAIL[/red]"
            table.add_row(check["name"], status, check["details"])
            if not check["passed"]:
                all_passed = False
        
        console.print(Panel(
            table,
            title="[bold green]✓ VERIFICATION COMPLETE[/bold green]" if all_passed 
                  else "[bold red]✗ VERIFICATION FAILED[/bold red]",
            border_style=COLORS["verify"] if all_passed else COLORS["error"]
        ))
        
        # Reset für nächste Verifikation
        self.checks = []
        
        return all_passed
    
    def show_extracted_claims(self, claims: Dict[str, Any]):
        """Zeigt die erfolgreich extrahierten Claims."""
        table = Table(
            title="Extrahierte & Verifizierte Daten",
            box=box.DOUBLE,
            border_style="green"
        )
        table.add_column("Attribut", style="cyan bold")
        table.add_column("Wert", style="white")
        
        for name, value in claims.items():
            display_name = name.replace("_", " ").title()
            table.add_row(display_name, str(value))
        
        console.print(Panel(
            table,
            title="[bold green]🎫 VERIFIZIERTE DATEN[/bold green]",
            border_style="green",
            subtitle="Nur die vom Holder freigegebenen Attribute"
        ))


# ============================================================================
# Globale Instanzen für einfachen Zugriff
# ============================================================================

crypto_insight = CryptoInsight()
traffic_monitor = TrafficMonitor()
verification_logic = VerificationLogic()


# ============================================================================
# Utility-Funktionen
# ============================================================================

def show_separator(title: str = "", style: str = "dim"):
    """Zeigt einen visuellen Trenner."""
    console.print()
    if title:
        console.rule(f"[{style}]{title}[/{style}]")
    else:
        console.rule(style=style)
    console.print()


def show_inspection_mode_banner():
    """Zeigt ein Banner für den Inspection-Modus."""
    console.print(Panel(
        "[bold]🔍 LIVE-INSPECTION MODE AKTIV[/bold]\n\n"
        "Alle kryptografischen Operationen und Netzwerk-Traffic\n"
        "werden in Echtzeit visualisiert.",
        title="Observability",
        border_style="yellow"
    ))
