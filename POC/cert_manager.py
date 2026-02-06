"""
ACME Certificate Manager - Python-native TLS-Zertifikatsverwaltung
Unterstützt Let's Encrypt mit Cloudflare DNS-01 Challenge

Plattformunabhängig: Windows & Linux

Verwendung:
    python cert_manager.py setup      # Erstmalige Einrichtung
    python cert_manager.py issue      # Zertifikate anfordern
    python cert_manager.py renew      # Zertifikate erneuern
    python cert_manager.py self-sign  # Selbstsignierte Zertifikate (Entwicklung)
"""

import os
import sys
import json
import time
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table

# Optionale Imports - werden bei Bedarf geladen
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import josepy as jose
    from acme import client, messages, challenges
    ACME_AVAILABLE = True
except ImportError:
    ACME_AVAILABLE = False

try:
    from cloudflare import Cloudflare
    CLOUDFLARE_AVAILABLE = True
except ImportError:
    CLOUDFLARE_AVAILABLE = False


# ============================================================================
# Konfiguration
# ============================================================================

CONFIG = {
    "certs_dir": "certs",
    "acme_dir": "certs/acme",
    "config_file": "certs/acme_config.json",
    
    # Let's Encrypt Endpoints
    "acme_directory_staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "acme_directory_production": "https://acme-v02.api.letsencrypt.org/directory",
    
    # Domains für Zertifikate
    "domains": {
        "issuer": {
            "domain": "issuer.example.com",
            "cert_file": "certs/issuer.crt",
            "key_file": "certs/issuer.key"
        },
        "verifier": {
            "domain": "verifier.example.com",
            "cert_file": "certs/verifier.crt",
            "key_file": "certs/verifier.key"
        }
    }
}

console = Console()


# ============================================================================
# Self-Signed Certificates (Entwicklung)
# ============================================================================

def generate_self_signed_cert(
    domain: str,
    cert_path: str,
    key_path: str,
    days_valid: int = 365
) -> bool:
    """
    Generiert ein selbstsigniertes Zertifikat.
    Für lokale Entwicklung ohne echte Domain.
    """
    if not CRYPTO_AVAILABLE:
        console.print("[red]✗[/red] 'cryptography' nicht installiert: pip install cryptography")
        return False
    
    console.print(f"[cyan]...[/cyan] Generiere selbstsigniertes Zertifikat für {domain}")
    
    # Private Key generieren (RSA 2048)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Subject und Issuer (selbstsigniert = gleich)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Baden-Wuerttemberg"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Stuttgart"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DHBW SD-JWT PoC"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])
    
    # Zertifikat erstellen
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain),
                x509.DNSName("localhost"),
                x509.IPAddress(__import__('ipaddress').IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    # Verzeichnis erstellen
    Path(cert_path).parent.mkdir(parents=True, exist_ok=True)
    
    # Private Key speichern
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Zertifikat speichern
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    console.print(f"[green]✓[/green] Zertifikat erstellt: {cert_path}")
    console.print(f"[green]✓[/green] Private Key erstellt: {key_path}")
    
    return True


def generate_all_self_signed():
    """Generiert selbstsignierte Zertifikate für alle konfigurierten Domains."""
    console.print(Panel(
        "[bold]Selbstsignierte Zertifikate generieren[/bold]\n\n"
        "Diese Zertifikate sind nur für lokale Entwicklung geeignet.\n"
        "Browser werden Warnungen anzeigen.",
        title="🔐 Self-Signed Certificates",
        border_style="yellow"
    ))
    
    for name, config in CONFIG["domains"].items():
        domain = config["domain"]
        
        # Für localhost anpassen
        if Confirm.ask(f"Für '{name}' localhost verwenden statt {domain}?", default=True):
            domain = "localhost"
        
        success = generate_self_signed_cert(
            domain=domain,
            cert_path=config["cert_file"],
            key_path=config["key_file"]
        )
        
        if not success:
            return False
    
    console.print("\n[green]✓[/green] Alle Zertifikate erstellt!")
    console.print("[dim]Starte Issuer/Verifier neu, um die Zertifikate zu laden.[/dim]")
    return True


# ============================================================================
# ACME / Let's Encrypt
# ============================================================================

class AcmeCertManager:
    """
    ACME Certificate Manager mit Cloudflare DNS-01 Challenge.
    Python-native Implementierung ohne externe Tools.
    """
    
    def __init__(self, use_staging: bool = True):
        self.use_staging = use_staging
        self.directory_url = (
            CONFIG["acme_directory_staging"] if use_staging 
            else CONFIG["acme_directory_production"]
        )
        self.account_key_path = Path(CONFIG["acme_dir"]) / "account.key"
        self.config_path = Path(CONFIG["config_file"])
        self.cf_client = None
        self.acme_client = None
        
    def check_dependencies(self) -> bool:
        """Prüft ob alle Abhängigkeiten installiert sind."""
        missing = []
        
        if not CRYPTO_AVAILABLE:
            missing.append("cryptography")
        if not ACME_AVAILABLE:
            missing.append("acme josepy")
        if not CLOUDFLARE_AVAILABLE:
            missing.append("cloudflare")
        
        if missing:
            console.print("[red]✗[/red] Fehlende Abhängigkeiten:")
            console.print(f"    pip install {' '.join(missing)}")
            return False
        
        return True
    
    def load_config(self) -> dict:
        """Lädt die ACME-Konfiguration."""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                return json.load(f)
        return {}
    
    def save_config(self, config: dict):
        """Speichert die ACME-Konfiguration."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
    
    def setup_cloudflare(self, api_token: str) -> bool:
        """Initialisiert den Cloudflare Client."""
        try:
            # cloudflare SDK v4+
            self.cf_client = Cloudflare(api_token=api_token)
            # Test: Zonen abrufen
            zones_response = self.cf_client.zones.list()
            zones = list(zones_response)
            console.print(f"[green]✓[/green] Cloudflare API verbunden ({len(zones)} Zonen)")
            return True
        except Exception as e:
            console.print(f"[red]✗[/red] Cloudflare API Fehler: {e}")
            return False
    
    def get_zone_id(self, domain: str) -> Optional[str]:
        """Findet die Zone-ID für eine Domain."""
        # Extrahiere Root-Domain (z.B. example.com aus sub.example.com)
        parts = domain.split('.')
        for i in range(len(parts) - 1):
            zone_name = '.'.join(parts[i:])
            try:
                zones_response = self.cf_client.zones.list(name=zone_name)
                zones = list(zones_response)
                if zones:
                    return zones[0].id
            except:
                continue
        return None
    
    def create_dns_record(self, zone_id: str, name: str, content: str) -> Optional[str]:
        """Erstellt einen DNS TXT Record für die ACME Challenge."""
        try:
            record = self.cf_client.dns.records.create(
                zone_id=zone_id,
                type='TXT',
                name=name,
                content=content,
                ttl=120
            )
            return record.id
        except Exception as e:
            console.print(f"[red]✗[/red] DNS Record Fehler: {e}")
            return None
    
    def delete_dns_record(self, zone_id: str, record_id: str):
        """Löscht einen DNS TXT Record."""
        try:
            self.cf_client.dns.records.delete(dns_record_id=record_id, zone_id=zone_id)
        except:
            pass
    
    def generate_account_key(self) -> 'jose.JWKRSA':
        """Generiert oder lädt den ACME Account Key."""
        self.account_key_path.parent.mkdir(parents=True, exist_ok=True)
        
        if self.account_key_path.exists():
            console.print("[cyan]...[/cyan] Lade existierenden Account Key")
            with open(self.account_key_path, 'rb') as f:
                key_pem = f.read()
            private_key = serialization.load_pem_private_key(
                key_pem, password=None, backend=default_backend()
            )
        else:
            console.print("[cyan]...[/cyan] Generiere neuen Account Key")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            # Speichern
            with open(self.account_key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        
        return jose.JWKRSA(key=private_key)
    
    def register_account(self, email: str) -> bool:
        """Registriert einen ACME Account oder verwendet existierenden."""
        if not self.check_dependencies():
            return False
        
        console.print(f"[cyan]...[/cyan] Verbinde mit ACME Server...")
        console.print(f"[dim]  {self.directory_url}[/dim]")
        
        account_key = self.generate_account_key()
        
        # ACME Client erstellen
        net = client.ClientNetwork(account_key, user_agent="DHBW-SD-JWT-PoC/1.0")
        directory = messages.Directory.from_json(
            net.get(self.directory_url).json()
        )
        self.acme_client = client.ClientV2(directory, net)
        
        # Account registrieren oder existierenden verwenden
        console.print(f"[cyan]...[/cyan] Registriere Account: {email}")
        
        try:
            # Versuche neuen Account zu erstellen
            regr = self.acme_client.new_account(
                messages.NewRegistration.from_data(
                    email=email,
                    terms_of_service_agreed=True
                )
            )
            console.print("[green]✓[/green] Account registriert")
            
        except Exception as e:
            error_str = str(e).lower()
            if "already" in error_str or "existing" in error_str or "conflict" in error_str:
                # Account existiert bereits - versuche ihn zu laden
                console.print("[cyan]...[/cyan] Account existiert - lade existierenden")
                try:
                    regr = self.acme_client.new_account(
                        messages.NewRegistration.from_data(
                            email=email,
                            terms_of_service_agreed=True,
                            only_return_existing=True
                        )
                    )
                    console.print("[green]✓[/green] Existierenden Account geladen")
                except Exception as e2:
                    console.print(f"[red]✗[/red] Account-Laden fehlgeschlagen: {e2}")
                    return False
            else:
                console.print(f"[red]✗[/red] Registrierung fehlgeschlagen: {e}")
                return False
        
        # Config speichern
        config = self.load_config()
        config['email'] = email
        config['account_registered'] = True
        config['staging'] = self.use_staging
        self.save_config(config)
        
        return True
    
    def issue_certificate(self, domain: str, cert_path: str, key_path: str) -> bool:
        """
        Fordert ein Zertifikat für eine Domain an (DNS-01 Challenge).
        """
        if not self.acme_client:
            console.print("[red]✗[/red] ACME Client nicht initialisiert")
            return False
        
        console.print(f"\n[bold]Zertifikat für {domain}[/bold]")
        
        # 1. Private Key für Zertifikat generieren
        console.print("[cyan]...[/cyan] Generiere Certificate Key")
        cert_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # 2. CSR erstellen
        console.print("[cyan]...[/cyan] Erstelle CSR")
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False
        ).sign(cert_key, hashes.SHA256(), default_backend())
        
        # 3. Order erstellen
        console.print("[cyan]...[/cyan] Erstelle ACME Order")
        # CSR als PEM-Bytes für acme 5.x+
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        order = self.acme_client.new_order(csr_pem)
        
        # 4. DNS-01 Challenge bearbeiten
        for authz in order.authorizations:
            for challenge in authz.body.challenges:
                if isinstance(challenge.chall, challenges.DNS01):
                    return self._handle_dns_challenge(
                        domain, challenge, authz, order, 
                        cert_key, cert_path, key_path
                    )
        
        console.print("[red]✗[/red] Keine DNS-01 Challenge gefunden")
        return False
    
    def _handle_dns_challenge(
        self, domain: str, challenge, authz, order,
        cert_key, cert_path: str, key_path: str
    ) -> bool:
        """Führt die DNS-01 Challenge durch."""
        
        # DNS-01 Validation Value berechnen (acme 5.x+ Methode)
        # challenge.chall.validation() gibt den Base64-URL-encoded SHA-256 Hash zurück
        dns_value = challenge.chall.validation(self.acme_client.net.key)
        
        record_name = f"_acme-challenge.{domain}"
        
        console.print(f"[cyan]...[/cyan] Erstelle DNS Record:")
        console.print(f"    Name:  {record_name}")
        console.print(f"    Type:  TXT")
        console.print(f"    Value: {dns_value}")
        
        # Zone ID finden
        zone_id = self.get_zone_id(domain)
        if not zone_id:
            console.print(f"[red]✗[/red] Zone für {domain} nicht gefunden")
            return False
        
        # DNS Record erstellen
        record_id = self.create_dns_record(zone_id, record_name, dns_value)
        if not record_id:
            return False
        
        console.print("[green]✓[/green] DNS Record erstellt")
        
        try:
            # Warten bis DNS propagiert
            console.print("[cyan]...[/cyan] Warte auf DNS Propagation (30s)...")
            time.sleep(30)
            
            # Challenge antworten
            console.print("[cyan]...[/cyan] Antworte auf Challenge...")
            self.acme_client.answer_challenge(challenge, challenge.response(
                self.acme_client.net.key
            ))
            
            # Auf Validierung warten
            console.print("[cyan]...[/cyan] Warte auf Validierung...")
            order = self.acme_client.poll_and_finalize(order)
            
            # Zertifikat speichern
            Path(cert_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(key_path, 'wb') as f:
                f.write(cert_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open(cert_path, 'wb') as f:
                f.write(order.fullchain_pem.encode('utf-8'))
            
            console.print(f"[green]✓[/green] Zertifikat gespeichert: {cert_path}")
            console.print(f"[green]✓[/green] Private Key gespeichert: {key_path}")
            
            return True
            
        finally:
            # DNS Record aufräumen
            console.print("[cyan]...[/cyan] Lösche DNS Record...")
            self.delete_dns_record(zone_id, record_id)


def setup_acme():
    """Interaktives Setup für ACME/Let's Encrypt."""
    console.print(Panel(
        "[bold]ACME / Let's Encrypt Setup[/bold]\n\n"
        "Konfiguriert automatische TLS-Zertifikate mit Cloudflare DNS.",
        title="🔐 ACME Setup",
        border_style="cyan"
    ))
    
    # Staging oder Production?
    use_staging = Confirm.ask(
        "Staging-Server verwenden (zum Testen)?", 
        default=True
    )
    
    if not use_staging:
        console.print("[yellow]⚠[/yellow] Production-Server hat Rate Limits!")
        if not Confirm.ask("Wirklich Production verwenden?", default=False):
            use_staging = True
    
    manager = AcmeCertManager(use_staging=use_staging)
    
    if not manager.check_dependencies():
        console.print("\n[bold]Installiere fehlende Pakete:[/bold]")
        console.print("  pip install acme josepy cloudflare cryptography")
        return
    
    # Cloudflare API Token
    console.print("\n[bold]Cloudflare API Token:[/bold]")
    console.print("[dim]Erstelle unter: https://dash.cloudflare.com/profile/api-tokens[/dim]")
    console.print("[dim]Benötigte Berechtigung: Zone:DNS:Edit[/dim]")
    
    api_token = Prompt.ask("API Token", password=True)
    
    if not manager.setup_cloudflare(api_token):
        return
    
    # Email für Account
    email = Prompt.ask("Email für Let's Encrypt Account")
    
    if not manager.register_account(email):
        return
    
    # Config speichern (Token sicher speichern)
    config = manager.load_config()
    config['cloudflare_token'] = api_token
    manager.save_config(config)
    
    console.print("\n[green]✓[/green] Setup abgeschlossen!")
    console.print("[dim]Führe 'python cert_manager.py issue' aus, um Zertifikate zu erstellen.[/dim]")


def issue_certificates():
    """Fordert Zertifikate für alle konfigurierten Domains an."""
    config_path = Path(CONFIG["config_file"])
    
    if not config_path.exists():
        console.print("[red]✗[/red] Kein Setup gefunden. Führe erst 'setup' aus.")
        return
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    manager = AcmeCertManager(use_staging=config.get('staging', True))
    
    if not manager.check_dependencies():
        return
    
    # Cloudflare verbinden
    if not manager.setup_cloudflare(config.get('cloudflare_token', '')):
        return
    
    # Account laden
    if not manager.register_account(config.get('email', '')):
        return
    
    # Domains konfigurieren
    console.print("\n[bold]Domains konfigurieren:[/bold]")
    
    for name, domain_config in CONFIG["domains"].items():
        current_domain = domain_config["domain"]
        new_domain = Prompt.ask(f"Domain für {name}", default=current_domain)
        CONFIG["domains"][name]["domain"] = new_domain
    
    # Zertifikate anfordern
    for name, domain_config in CONFIG["domains"].items():
        success = manager.issue_certificate(
            domain=domain_config["domain"],
            cert_path=domain_config["cert_file"],
            key_path=domain_config["key_file"]
        )
        
        if not success:
            console.print(f"[red]✗[/red] Fehler bei {name}")


def show_status():
    """Zeigt den Status aller Zertifikate."""
    console.print(Panel(
        "[bold]Zertifikat-Status[/bold]",
        title="🔐 Status",
        border_style="blue"
    ))
    
    table = Table(title="Konfigurierte Zertifikate")
    table.add_column("Komponente", style="cyan")
    table.add_column("Domain", style="white")
    table.add_column("Zertifikat", style="green")
    table.add_column("Gültig bis", style="yellow")
    
    for name, config in CONFIG["domains"].items():
        cert_exists = Path(config["cert_file"]).exists()
        key_exists = Path(config["key_file"]).exists()
        
        status = "✓ Vorhanden" if cert_exists and key_exists else "✗ Fehlt"
        expiry = "-"
        
        if cert_exists and CRYPTO_AVAILABLE:
            try:
                with open(config["cert_file"], 'rb') as f:
                    cert = x509.load_pem_x509_certificate(f.read())
                expiry = cert.not_valid_after.strftime("%Y-%m-%d")
            except:
                expiry = "Fehler"
        
        table.add_row(name, config["domain"], status, expiry)
    
    console.print(table)


def show_help():
    """Zeigt die Hilfe an."""
    console.print(Panel(
        "[bold]ACME Certificate Manager[/bold]\n\n"
        "Plattformunabhängige Zertifikatsverwaltung für SD-JWT PoC.\n\n"
        "[bold]Befehle:[/bold]\n"
        "  [cyan]setup[/cyan]      Erstmalige ACME/Cloudflare Einrichtung\n"
        "  [cyan]issue[/cyan]      Zertifikate von Let's Encrypt anfordern\n"
        "  [cyan]renew[/cyan]      Zertifikate erneuern\n"
        "  [cyan]self-sign[/cyan]  Selbstsignierte Zertifikate (Entwicklung)\n"
        "  [cyan]status[/cyan]     Status aller Zertifikate anzeigen\n"
        "  [cyan]help[/cyan]       Diese Hilfe anzeigen\n\n"
        "[bold]Abhängigkeiten:[/bold]\n"
        "  pip install acme josepy cloudflare cryptography rich",
        title="🔐 Hilfe",
        border_style="blue"
    ))


# ============================================================================
# Main
# ============================================================================

def main():
    if len(sys.argv) < 2:
        show_help()
        return
    
    command = sys.argv[1].lower()
    
    if command == "setup":
        setup_acme()
    elif command == "issue":
        issue_certificates()
    elif command == "renew":
        issue_certificates()  # Gleiche Logik
    elif command in ["self-sign", "selfsign", "dev"]:
        generate_all_self_signed()
    elif command == "status":
        show_status()
    elif command in ["help", "-h", "--help"]:
        show_help()
    else:
        console.print(f"[red]Unbekannter Befehl: {command}[/red]")
        show_help()


if __name__ == "__main__":
    main()
