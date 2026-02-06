"""
Config Manager - Zentrale Konfigurationsverwaltung für SD-JWT PoC
Jede Komponente (Issuer, Verifier, Wallet) hat eigene persistente Konfiguration.

Verwendung:
    from config_manager import ComponentConfig
    
    config = ComponentConfig("issuer")
    CONFIG = config.load_or_setup()
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, List

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table

console = Console()

# ============================================================================
# Konfigurationsverzeichnis
# ============================================================================

CONFIGS_DIR = Path(__file__).parent / "configs"

# ============================================================================
# Default-Konfigurationen für jede Komponente
# ============================================================================

DEFAULT_CONFIGS = {
    "issuer": {
        "issuer_name": "Bundesamt für Digitale Identität",
        "issuer_uri": "https://localhost:5001",
        "host": "0.0.0.0",
        "port": 5001,
        "ssl": {
            "enabled": True,
            "cert_file": "certs/issuer.crt",
            "key_file": "certs/issuer.key",
            "mode": "self-signed",  # "self-signed" | "acme" | "manual"
            "acme": {
                "domain": "",
                "email": "",
                "cloudflare_token": "",
                "use_staging": True
            }
        },
        "status_list_size": 1000,
        "citizen_db_path": "citizen_db.json",
        "keys_path": "issuer_keys.json",
        "inspection_mode": True,
        "add_decoys": True,
        "decoy_count": 2,
        "first_run_completed": False
    },
    
    "verifier": {
        "verifier_name": "Altersverifikation Service",
        "verifier_uri": "https://localhost:5002",
        "host": "0.0.0.0",
        "port": 5002,
        "ssl": {
            "enabled": True,
            "cert_file": "certs/verifier.crt",
            "key_file": "certs/verifier.key",
            "mode": "self-signed",
            "acme": {
                "domain": "",
                "email": "",
                "cloudflare_token": "",
                "use_staging": True
            }
        },
        "challenge_validity_minutes": 5,
        "trust_registry_file": "trusted_registry.json",
        "clock_skew_seconds": 60,
        "inspection_mode": True,
        "trusted_issuers": ["https://localhost:5001", "http://localhost:5001"],
        "first_run_completed": False
    },
    
    "wallet": {
        "default_issuer": "https://localhost:5001",
        "default_verifier": "https://localhost:5002",
        "wallet_store_path": "wallet_store.json",
        "inspection_mode": True,
        "first_run_completed": False
    }
}

# ============================================================================
# Interaktive Prompts pro Komponente
# ============================================================================

SETUP_PROMPTS = {
    "issuer": [
        {
            "key": "issuer_name",
            "question": "Name des Issuers",
            "default": "Bundesamt für Digitale Identität",
            "type": "text"
        },
        {
            "key": "port",
            "question": "Server-Port",
            "default": "5001",
            "type": "int"
        },
        {
            "key": "ssl.enabled",
            "question": "TLS/HTTPS aktivieren?",
            "default": True,
            "type": "confirm"
        },
        {
            "key": "ssl.mode",
            "question": "TLS-Modus",
            "options": ["self-signed", "acme", "manual"],
            "default": "self-signed",
            "type": "choice",
            "condition": "ssl.enabled"
        },
        {
            "key": "ssl.acme.domain",
            "question": "Domain für Let's Encrypt Zertifikat",
            "default": "",
            "type": "text",
            "condition": "ssl.mode==acme"
        },
        {
            "key": "ssl.acme.email",
            "question": "E-Mail für Let's Encrypt Account",
            "default": "",
            "type": "text",
            "condition": "ssl.mode==acme"
        },
        {
            "key": "ssl.acme.cloudflare_token",
            "question": "Cloudflare API Token (Zone:DNS:Edit)",
            "default": "",
            "type": "password",
            "condition": "ssl.mode==acme"
        },
        {
            "key": "ssl.acme.use_staging",
            "question": "Let's Encrypt Staging verwenden (zum Testen)?",
            "default": True,
            "type": "confirm",
            "condition": "ssl.mode==acme"
        },
        {
            "key": "issuer_uri",
            "question": "Öffentliche URL des Issuers",
            "default_from": "_compute_issuer_uri",
            "type": "text"
        },
        {
            "key": "inspection_mode",
            "question": "Inspection Mode aktivieren (zeigt Crypto-Details)?",
            "default": True,
            "type": "confirm"
        }
    ],
    
    "verifier": [
        {
            "key": "verifier_name",
            "question": "Name des Verifiers",
            "default": "Altersverifikation Service",
            "type": "text"
        },
        {
            "key": "port",
            "question": "Server-Port",
            "default": "5002",
            "type": "int"
        },
        {
            "key": "ssl.enabled",
            "question": "TLS/HTTPS aktivieren?",
            "default": True,
            "type": "confirm"
        },
        {
            "key": "ssl.mode",
            "question": "TLS-Modus",
            "options": ["self-signed", "acme", "manual"],
            "default": "self-signed",
            "type": "choice",
            "condition": "ssl.enabled"
        },
        {
            "key": "ssl.acme.domain",
            "question": "Domain für Let's Encrypt Zertifikat",
            "default": "",
            "type": "text",
            "condition": "ssl.mode==acme"
        },
        {
            "key": "ssl.acme.email",
            "question": "E-Mail für Let's Encrypt Account",
            "default": "",
            "type": "text",
            "condition": "ssl.mode==acme"
        },
        {
            "key": "ssl.acme.cloudflare_token",
            "question": "Cloudflare API Token (Zone:DNS:Edit)",
            "default": "",
            "type": "password",
            "condition": "ssl.mode==acme"
        },
        {
            "key": "ssl.acme.use_staging",
            "question": "Let's Encrypt Staging verwenden (zum Testen)?",
            "default": True,
            "type": "confirm",
            "condition": "ssl.mode==acme"
        },
        {
            "key": "verifier_uri",
            "question": "Öffentliche URL des Verifiers",
            "default_from": "_compute_verifier_uri",
            "type": "text"
        },
        {
            "key": "trusted_issuers",
            "question": "Vertrauenswürdige Issuer (kommasepariert)",
            "default": "https://localhost:5001",
            "type": "list"
        },
        {
            "key": "inspection_mode",
            "question": "Inspection Mode aktivieren (zeigt Verifikations-Details)?",
            "default": True,
            "type": "confirm"
        }
    ],
    
    "wallet": [
        {
            "key": "default_issuer",
            "question": "Standard-Issuer URL",
            "default": "https://localhost:5001",
            "type": "text"
        },
        {
            "key": "default_verifier",
            "question": "Standard-Verifier URL",
            "default": "https://localhost:5002",
            "type": "text"
        },
        {
            "key": "wallet_store_path",
            "question": "Speicherpfad für Wallet-Daten",
            "default": "wallet_store.json",
            "type": "text"
        },
        {
            "key": "inspection_mode",
            "question": "Inspection Mode aktivieren (zeigt Traffic-Details)?",
            "default": True,
            "type": "confirm"
        }
    ]
}


# ============================================================================
# ComponentConfig Klasse
# ============================================================================

class ComponentConfig:
    """
    Verwaltet die Konfiguration einer einzelnen Komponente.
    Unterstützt First-Run Setup mit interaktiven Prompts.
    """
    
    def __init__(self, component: str):
        """
        Initialisiert den Config-Manager.
        
        Args:
            component: "issuer" | "verifier" | "wallet"
        """
        if component not in DEFAULT_CONFIGS:
            raise ValueError(f"Unbekannte Komponente: {component}")
        
        self.component = component
        self.config_dir = CONFIGS_DIR
        self.config_path = self.config_dir / f"{component}_config.json"
        self._config: Dict[str, Any] = {}
    
    def load_or_setup(self) -> Dict[str, Any]:
        """
        Lädt existierende Konfiguration oder startet First-Run Setup.
        
        Returns:
            Die geladene/erstellte Konfiguration
        """
        # Verzeichnis erstellen falls nötig
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        if self.is_first_run():
            return self.run_first_time_setup()
        
        return self.load_config()
    
    def is_first_run(self) -> bool:
        """Prüft ob dies der erste Start der Komponente ist."""
        if not self.config_path.exists():
            return True
        
        try:
            config = self.load_config()
            return not config.get("first_run_completed", False)
        except Exception:
            return True
    
    def load_config(self) -> Dict[str, Any]:
        """Lädt die Konfiguration aus der JSON-Datei."""
        if not self.config_path.exists():
            # Default-Konfiguration zurückgeben
            self._config = DEFAULT_CONFIGS[self.component].copy()
            return self._config
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            self._config = json.load(f)
        
        # Fehlende Keys mit Defaults auffüllen
        self._merge_defaults()
        
        return self._config
    
    def save_config(self) -> None:
        """Speichert die Konfiguration in die JSON-Datei."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        with open(self.config_path, 'w', encoding='utf-8') as f:
            json.dump(self._config, f, indent=2, ensure_ascii=False)
    
    def _merge_defaults(self) -> None:
        """Fügt fehlende Default-Werte zur geladenen Config hinzu."""
        defaults = DEFAULT_CONFIGS[self.component]
        self._config = self._deep_merge(defaults, self._config)
    
    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """Merged zwei Dictionaries rekursiv."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    def run_first_time_setup(self) -> Dict[str, Any]:
        """
        Führt den interaktiven First-Run Setup durch.
        
        Returns:
            Die erstellte Konfiguration
        """
        # Starte mit Defaults
        self._config = self._deep_copy(DEFAULT_CONFIGS[self.component])
        
        # Banner anzeigen
        component_names = {
            "issuer": ("🏛️", "ISSUER", "blue"),
            "verifier": ("🔍", "VERIFIER", "green"),
            "wallet": ("👛", "WALLET", "magenta")
        }
        
        icon, name, color = component_names[self.component]
        
        console.print()
        console.print(Panel(
            f"[bold]Willkommen beim {name}![/bold]\n\n"
            "Dieser Assistent konfiguriert die notwendigen Einstellungen.\n"
            "Drücke [bold]Enter[/bold] für den Standardwert.",
            title=f"{icon} {name} - Ersteinrichtung",
            border_style=color
        ))
        console.print()
        
        # Prompts durcharbeiten
        prompts = SETUP_PROMPTS.get(self.component, [])
        
        for prompt_config in prompts:
            # Bedingung prüfen
            if not self._check_condition(prompt_config.get("condition")):
                continue
            
            # Wert abfragen
            value = self._prompt_for_value(prompt_config)
            
            # Wert setzen (unterstützt nested keys wie "ssl.enabled")
            self._set_nested_value(prompt_config["key"], value)
        
        # URI berechnen falls nötig
        self._compute_uris()
        
        # First-Run als abgeschlossen markieren
        self._config["first_run_completed"] = True
        
        # Speichern
        self.save_config()
        
        console.print()
        console.print(f"[green]✓[/green] Konfiguration gespeichert: [dim]{self.config_path}[/dim]")
        console.print()
        
        # TLS-Zertifikate erstellen falls nötig
        self._setup_certificates()
        
        return self._config
    
    def _check_condition(self, condition: Optional[str]) -> bool:
        """Prüft ob eine Bedingung erfüllt ist."""
        if not condition:
            return True
        
        # Einfache Bedingung: "ssl.enabled"
        if "==" not in condition:
            value = self._get_nested_value(condition)
            return bool(value)
        
        # Vergleichs-Bedingung: "ssl.mode==acme"
        key, expected = condition.split("==", 1)
        actual = self._get_nested_value(key.strip())
        return str(actual) == expected.strip()
    
    def _prompt_for_value(self, prompt_config: Dict) -> Any:
        """Fragt einen Wert vom Benutzer ab."""
        question = prompt_config["question"]
        prompt_type = prompt_config.get("type", "text")
        
        # Default-Wert ermitteln
        default = prompt_config.get("default", "")
        if "default_from" in prompt_config:
            # Dynamischer Default
            default = self._compute_default(prompt_config["default_from"])
        
        if prompt_type == "text":
            return Prompt.ask(f"  {question}", default=str(default))
        
        elif prompt_type == "password":
            return Prompt.ask(f"  {question}", password=True, default=str(default))
        
        elif prompt_type == "int":
            result = Prompt.ask(f"  {question}", default=str(default))
            try:
                return int(result)
            except ValueError:
                return int(default) if default else 0
        
        elif prompt_type == "confirm":
            return Confirm.ask(f"  {question}", default=bool(default))
        
        elif prompt_type == "choice":
            options = prompt_config.get("options", [])
            console.print(f"  {question}:")
            for i, opt in enumerate(options, 1):
                marker = "[green]>[/green]" if opt == default else " "
                console.print(f"    {marker} [{i}] {opt}")
            
            choice = Prompt.ask("  Auswahl", default="1")
            try:
                idx = int(choice) - 1
                return options[idx] if 0 <= idx < len(options) else default
            except (ValueError, IndexError):
                return default
        
        elif prompt_type == "list":
            result = Prompt.ask(f"  {question}", default=str(default))
            return [x.strip() for x in result.split(",") if x.strip()]
        
        return default
    
    def _compute_default(self, method: str) -> str:
        """Berechnet einen dynamischen Default-Wert."""
        if method == "_compute_issuer_uri":
            ssl_enabled = self._get_nested_value("ssl.enabled")
            port = self._get_nested_value("port")
            ssl_mode = self._get_nested_value("ssl.mode")
            
            if ssl_mode == "acme":
                domain = self._get_nested_value("ssl.acme.domain")
                if domain:
                    return f"https://{domain}"
            
            protocol = "https" if ssl_enabled else "http"
            return f"{protocol}://localhost:{port}"
        
        elif method == "_compute_verifier_uri":
            ssl_enabled = self._get_nested_value("ssl.enabled")
            port = self._get_nested_value("port")
            ssl_mode = self._get_nested_value("ssl.mode")
            
            if ssl_mode == "acme":
                domain = self._get_nested_value("ssl.acme.domain")
                if domain:
                    return f"https://{domain}"
            
            protocol = "https" if ssl_enabled else "http"
            return f"{protocol}://localhost:{port}"
        
        return ""
    
    def _compute_uris(self) -> None:
        """Aktualisiert URIs basierend auf Konfiguration."""
        if self.component == "issuer":
            ssl = self._get_nested_value("ssl.enabled")
            port = self._get_nested_value("port")
            mode = self._get_nested_value("ssl.mode")
            
            if mode == "acme":
                domain = self._get_nested_value("ssl.acme.domain")
                if domain:
                    # SSL-Pfade für ACME anpassen
                    self._set_nested_value("ssl.cert_file", f"certs/acme/{domain}.crt")
                    self._set_nested_value("ssl.key_file", f"certs/acme/{domain}.key")
        
        elif self.component == "verifier":
            mode = self._get_nested_value("ssl.mode")
            
            if mode == "acme":
                domain = self._get_nested_value("ssl.acme.domain")
                if domain:
                    self._set_nested_value("ssl.cert_file", f"certs/acme/{domain}.crt")
                    self._set_nested_value("ssl.key_file", f"certs/acme/{domain}.key")
    
    def _setup_certificates(self) -> None:
        """Erstellt TLS-Zertifikate wenn nötig."""
        ssl_enabled = self._get_nested_value("ssl.enabled")
        if not ssl_enabled:
            return
        
        ssl_mode = self._get_nested_value("ssl.mode")
        cert_file = self._get_nested_value("ssl.cert_file")
        key_file = self._get_nested_value("ssl.key_file")
        
        # Prüfen ob Zertifikate existieren
        if os.path.exists(cert_file) and os.path.exists(key_file):
            console.print(f"[green]✓[/green] TLS-Zertifikate vorhanden")
            return
        
        if ssl_mode == "self-signed":
            console.print("[cyan]...[/cyan] Erstelle selbstsignierte Zertifikate...")
            self._generate_self_signed_cert(cert_file, key_file)
        
        elif ssl_mode == "acme":
            console.print("[cyan]...[/cyan] Fordere Let's Encrypt Zertifikate an...")
            self._request_acme_cert()
        
        elif ssl_mode == "manual":
            console.print(f"[yellow]![/yellow] Manuelle Zertifikate erwartet:")
            console.print(f"    Zertifikat: {cert_file}")
            console.print(f"    Private Key: {key_file}")
    
    def _generate_self_signed_cert(self, cert_file: str, key_file: str) -> None:
        """Generiert selbstsignierte Zertifikate."""
        try:
            from cert_manager import generate_self_signed_cert
            
            # Domain für Zertifikat
            if self.component == "issuer":
                domain = "issuer.local"
            else:
                domain = "verifier.local"
            
            success = generate_self_signed_cert(
                domain=domain,
                cert_path=cert_file,
                key_path=key_file
            )
            
            if success:
                console.print(f"[green]✓[/green] Selbstsigniertes Zertifikat erstellt")
            else:
                console.print(f"[red]✗[/red] Zertifikat-Erstellung fehlgeschlagen")
        
        except ImportError:
            console.print("[yellow]![/yellow] cert_manager.py nicht gefunden")
            console.print("[dim]  Führe 'python cert_manager.py self-sign' manuell aus[/dim]")
    
    def _request_acme_cert(self) -> None:
        """Fordert Let's Encrypt Zertifikate an."""
        try:
            from cert_manager import AcmeCertManager
            
            domain = self._get_nested_value("ssl.acme.domain")
            email = self._get_nested_value("ssl.acme.email")
            token = self._get_nested_value("ssl.acme.cloudflare_token")
            staging = self._get_nested_value("ssl.acme.use_staging")
            
            manager = AcmeCertManager(use_staging=staging)
            
            if not manager.check_dependencies():
                console.print("[red]✗[/red] ACME-Dependencies fehlen")
                console.print("  pip install acme josepy cloudflare")
                return
            
            if not manager.setup_cloudflare(token):
                console.print("[red]✗[/red] Cloudflare-Verbindung fehlgeschlagen")
                return
            
            if not manager.register_account(email):
                console.print("[red]✗[/red] ACME-Account-Registrierung fehlgeschlagen")
                return
            
            cert_file = self._get_nested_value("ssl.cert_file")
            key_file = self._get_nested_value("ssl.key_file")
            
            success = manager.issue_certificate(
                domain=domain,
                cert_path=cert_file,
                key_path=key_file
            )
            
            if success:
                console.print(f"[green]✓[/green] Let's Encrypt Zertifikat erhalten")
            else:
                console.print(f"[red]✗[/red] Zertifikat-Anforderung fehlgeschlagen")
        
        except ImportError:
            console.print("[yellow]![/yellow] cert_manager.py nicht verfügbar")
    
    def _get_nested_value(self, key: str) -> Any:
        """Holt einen Wert aus verschachtelter Config."""
        parts = key.split(".")
        value = self._config
        
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return None
        
        return value
    
    def _set_nested_value(self, key: str, value: Any) -> None:
        """Setzt einen Wert in verschachtelter Config."""
        parts = key.split(".")
        target = self._config
        
        for part in parts[:-1]:
            if part not in target:
                target[part] = {}
            target = target[part]
        
        target[parts[-1]] = value
    
    def _deep_copy(self, obj: Any) -> Any:
        """Erstellt eine tiefe Kopie eines Objekts."""
        if isinstance(obj, dict):
            return {k: self._deep_copy(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deep_copy(v) for v in obj]
        else:
            return obj
    
    def show_config(self) -> None:
        """Zeigt die aktuelle Konfiguration an."""
        if not self._config:
            self.load_config()
        
        console.print(Panel(
            f"[bold]{self.component.upper()} Konfiguration[/bold]",
            border_style="blue"
        ))
        
        table = Table(show_header=True)
        table.add_column("Einstellung", style="cyan")
        table.add_column("Wert", style="white")
        
        self._add_config_rows(table, self._config)
        
        console.print(table)
        console.print(f"\n[dim]Datei: {self.config_path}[/dim]")
    
    def _add_config_rows(self, table: Table, config: Dict, prefix: str = "") -> None:
        """Fügt Konfigurationszeilen zur Tabelle hinzu."""
        for key, value in config.items():
            full_key = f"{prefix}{key}" if prefix else key
            
            if isinstance(value, dict):
                self._add_config_rows(table, value, f"{full_key}.")
            elif isinstance(value, list):
                table.add_row(full_key, ", ".join(str(v) for v in value))
            elif key in ["cloudflare_token", "private"]:
                # Sensible Daten maskieren
                table.add_row(full_key, "****" if value else "[dim]nicht gesetzt[/dim]")
            else:
                table.add_row(full_key, str(value))
    
    def reset(self) -> None:
        """Setzt die Konfiguration zurück (löscht Config-Datei)."""
        if self.config_path.exists():
            self.config_path.unlink()
            console.print(f"[yellow]![/yellow] Konfiguration gelöscht: {self.config_path}")
        
        self._config = {}


# ============================================================================
# Hilfsfunktionen für Komponenten
# ============================================================================

def get_flat_config(component: str) -> Dict[str, Any]:
    """
    Lädt Config und flacht sie für Rückwärtskompatibilität ab.
    
    Konvertiert nested SSL-Config zu flachen Keys wie:
    - ssl_cert -> ssl.cert_file
    - ssl_key -> ssl.key_file
    
    Returns:
        Flaches Config-Dict kompatibel mit altem CONFIG-Format
    """
    config_mgr = ComponentConfig(component)
    config = config_mgr.load_or_setup()
    
    # Für Rückwärtskompatibilität: flache Keys erstellen
    flat = config.copy()
    
    if "ssl" in config:
        ssl = config["ssl"]
        flat["ssl_cert"] = ssl.get("cert_file", "")
        flat["ssl_key"] = ssl.get("key_file", "")
    
    return flat


# ============================================================================
# CLI für Testing
# ============================================================================

def main():
    """CLI für Konfigurationsverwaltung."""
    import sys
    
    if len(sys.argv) < 2:
        console.print("[bold]Config Manager[/bold]")
        console.print()
        console.print("Verwendung:")
        console.print("  python config_manager.py <component> [command]")
        console.print()
        console.print("Komponenten: issuer, verifier, wallet")
        console.print()
        console.print("Befehle:")
        console.print("  setup   - Konfiguration erstellen/ändern")
        console.print("  show    - Aktuelle Konfiguration anzeigen")
        console.print("  reset   - Konfiguration zurücksetzen")
        return
    
    component = sys.argv[1].lower()
    command = sys.argv[2].lower() if len(sys.argv) > 2 else "show"
    
    if component not in ["issuer", "verifier", "wallet"]:
        console.print(f"[red]Unbekannte Komponente: {component}[/red]")
        return
    
    config_mgr = ComponentConfig(component)
    
    if command == "setup":
        config_mgr._config = config_mgr._deep_copy(DEFAULT_CONFIGS[component])
        config_mgr.run_first_time_setup()
    
    elif command == "show":
        config_mgr.load_config()
        config_mgr.show_config()
    
    elif command == "reset":
        if Confirm.ask(f"Konfiguration für {component} wirklich löschen?", default=False):
            config_mgr.reset()
    
    else:
        console.print(f"[red]Unbekannter Befehl: {command}[/red]")


if __name__ == "__main__":
    main()
