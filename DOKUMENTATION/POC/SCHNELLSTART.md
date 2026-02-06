# Schnellstart-Anleitung

Diese Anleitung führt dich durch eine vollständige Demo des SD-JWT VC Systems.

## Voraussetzungen

- Python 3.10+
- 3 Terminal-Fenster

## 1. Installation (einmalig)

```powershell
cd POC
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Server starten

### Terminal 1: Issuer
```powershell
cd POC
.\venv\Scripts\activate
python issuer.py
```

### Terminal 2: Verifier
```powershell
cd POC
.\venv\Scripts\activate
python verifier.py
```

### Terminal 3: Wallet
```powershell
cd POC
.\venv\Scripts\activate
python wallet.py
```

## 3. Demo durchführen

### Schritt 1: Credential ausstellen

**Im Issuer-Terminal:**
```
issuer> offer 1234-CODE
```

→ Kopiere den angezeigten **Pre-Authorized Code**

### Schritt 2: Credential empfangen

**Im Wallet-Terminal:**
```
wallet> receive
Issuer URL [http://localhost:5001]: <Enter>
Pre-Authorized Code: <Paste Code>
```

→ Das Credential wird gespeichert

### Schritt 3: Credential anzeigen

**Im Wallet-Terminal:**
```
wallet> list
```

### Schritt 4: Credential präsentieren

**Im Wallet-Terminal:**
```
wallet> present
Verifier URL [http://localhost:5002]: <Enter>
```

→ Wähle Claims aus (z.B. `1,2` für Name und Geburtsdatum)
→ Bestätige mit `y`

### Schritt 5: Verifikation prüfen

**Im Verifier-Terminal:**
Der Verifier zeigt automatisch die verifizierten Daten an.

## 4. Erweiterte Funktionen

### Credential widerrufen (Revocation)

**Im Issuer-Terminal:**
```
issuer> revoke 0
```

→ Bei der nächsten Präsentation wird das Credential abgelehnt

### Mehrere Bürger

Verfügbare Codes in der Demo-Datenbank:
- `1234-CODE` - Max Mustermann
- `5678-CODE` - Erika Musterfrau
- `9999-CODE` - Hans Schmidt
- `ABCD-CODE` - Anna Müller

## Fehlerbehebung

| Problem | Lösung |
|---------|--------|
| "ModuleNotFoundError" | Prüfe ob venv aktiviert ist |
| "Connection refused" | Prüfe ob Server laufen |
| "Invalid grant" | Code bereits verwendet oder abgelaufen |
| "Untrusted issuer" | Issuer URL prüfen |

## Nächste Schritte

- Lies die vollständige [DOKUMENTATION.md](DOKUMENTATION.md)
- Experimentiere mit verschiedenen Claim-Kombinationen
- Teste die Revocation-Funktion
