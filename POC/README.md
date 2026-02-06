# SD-JWT VC Proof of Concept

Dieses Verzeichnis enthält die Implementierung eines **Selective Disclosure Verifiable Credential Systems** basierend auf dem SD-JWT Standard.

## Komponenten

| Datei | Beschreibung |
|-------|--------------|
| `sd_jwt_utils.py` | Shared Library mit Krypto-Funktionen |
| `issuer.py` | Issuer Server (Behörde) |
| `wallet.py` | Wallet Client (Bürger) |
| `verifier.py` | Verifier Server (Prüfstelle) |
| `citizen_db.json` | Demo-Bürgerdatenbank |
| `requirements.txt` | Python-Abhängigkeiten |

## Schnellstart

### 1. Installation

```bash
# Virtual Environment erstellen (empfohlen)
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Abhängigkeiten installieren
pip install -r requirements.txt
```

### 2. Issuer starten (Terminal 1)

```bash
python issuer.py
```

### 3. Verifier starten (Terminal 2)

```bash
python verifier.py
```

### 4. Wallet starten (Terminal 3)

```bash
python wallet.py
```

## Typischer Ablauf

### Credential ausstellen (Issuer → Wallet)

1. **Issuer:** `offer 1234-CODE` - Erstellt ein Credential-Angebot
2. **Wallet:** `receive` - Gibt den Pre-Authorized Code ein
3. **Wallet:** Credential wird automatisch gespeichert

### Credential präsentieren (Wallet → Verifier)

1. **Wallet:** `present` - Wählt Credential und Claims aus
2. **Verifier:** Zeigt verifizierte Daten an

### Credential widerrufen (Issuer)

```
issuer> revoke 0
```

## Befehle

### Issuer
- `offer <code>` - Credential Offer erstellen
- `list` - Alle Bürger anzeigen
- `revoke <index>` - Credential widerrufen
- `status` - Server-Status
- `help` - Hilfe

### Wallet
- `receive` - Credential empfangen
- `present` - Credential präsentieren
- `list` - Gespeicherte Credentials
- `delete` - Credential löschen
- `keys` - Schlüssel anzeigen
- `help` - Hilfe

### Verifier
- `request` - Verification Request erstellen
- `challenges` - Offene Challenges anzeigen
- `clear` - Abgelaufene Challenges löschen
- `status` - Server-Status
- `help` - Hilfe

## Ports

- Issuer: `http://localhost:5001`
- Verifier: `http://localhost:5002`

## Hinweise

- Dies ist ein **Proof of Concept** für Bildungszwecke
- HTTPS ist in der Produktionsumgebung erforderlich
- SSL-Warnungen werden für den PoC unterdrückt
