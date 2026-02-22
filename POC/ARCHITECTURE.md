# Systemarchitektur-Plan: SD-JWT VC Proof of Concept (Terminal & Python) 

## Version 1.0 - Stand: November 3, 2025

## 1. Projektübersicht
Dieses Dokument dient als Implementierungsleitfaden für ein **Selective Disclosure Verifiable Credential System (SD-JWT)**. Es handelt sich um einen universitären Proof of Concept (PoC), der die Standards OID4VCI (Issuance) und OID4VP (Presentation) in einer vereinfachten, terminalbasierten Umgebung umsetzt.

### Kerntechnologien
*   **Sprache:** Python 3.10+
*   **Server-Framework (Issuer/Verifier):** Flask (REST API)
*   **Client (Wallet):** Python Terminal App
*   **Kryptografie:** Ed25519 (Elliptic Curve) für Signaturen (Issuance & Key Binding).
*   **Netzwerk:** HTTPS (erzwungen) via Cloudflare DNS ACME Zertifikaten.
*   **UI/UX:** Terminal-Design-Bibliotheken (z. B. `rich` oder `Textual`) für ästhetischen Output.
*   **Infrastruktur:** 3 separate Maschinen (Issuer, Wallet, Verifier).

---

## 2. Kryptografische Grundlagen & SD-JWT Struktur
Das System muss den IETF SD-JWT Standard implementieren.

### 2.1 Algorithmen
*   **Signatur:** `EdDSA` mit Kurve `Ed25519`,.
*   **Hashing:** `SHA-256` für die Digests der Disclosures.
*   **Key Binding:** Der Holder muss Besitz des Credentials durch Signatur eines Nonce beweisen (Key Binding JWT),.

### 2.2 Token-Aufbau (Datenmodell)
Das Credential besteht aus drei Teilen, die logisch getrennt, aber mathematisch verbunden sind:

1.  **SD-JWT (Issuer Signed):** Enthält `_sd` (Array von Hashes) und `cnf` (Confirmation Key des Holders).
2.  **Disclosures:** Base64-Strings der Struktur `[Salt, Claim-Name, Claim-Wert]`.
3.  **Key Binding JWT (KB-JWT):** Vom Holder signiert, enthält `nonce` und `aud` (Verifier) sowie einen Hash des SD-JWTs.

---

## 3. Komponenten-Spezifikation

### Komponente A: Der Issuer (Server)
**Rolle:** Erstellt Credential Offers, hasht Claims und signiert den SD-JWT.
**Tech Stack:** Python Flask, `jwcrypto` oder `authlib`.

#### Endpunkte (REST API):
1.  **GET** `/.well-known/openid-credential-issuer`
    *   Liefert Metadata (Public Keys, unterstützte Credentials),.
2.  **POST** `/credential` (OID4VCI light)
    *   **Input:** Proof of Possession (JWT signiert mit Wallet-Key), angeforderte Claims.
    *   **Prozess:**
        1.  Verifizierung der Wallet-Signatur (Proof of Possession).
        2.  Generierung von Salt für jeden Claim.
        3.  Erstellung der Disclosures: `[Salt, Key, Value]`.
        4.  Hashing der Disclosures (SHA-256).
        5.  Erstellung des SD-JWT Payload (Hashes in `_sd` Array).
        6.  Signieren mit Issuer Private Key (Ed25519).
    *   **Output:** JSON mit `sd_jwt` (String) und `disclosures` (Array von Strings).

#### Terminal Output:
*   Muss mittels `rich` Logs in Farbe anzeigen: "Empfange Issuance Request...", "Erstelle Hashes...", "Signatur erstellt.".

---

### Komponente B: Die Wallet (Client)
**Rolle:** Verwaltet Keys, speichert Credentials, selektiert Claims, generiert Präsentationen.
**Tech Stack:** Python, `rich` (für TUI/Dashboard), `requests`.

#### Funktionalität & Flow:
1.  **Setup / KeyGen:**
    *   Beim Start prüfen, ob ein Ed25519 Keypair existiert. Wenn nicht, generieren und sicher (lokal) speichern.
2.  **Issuance (Empfangen):**
    *   User wählt Issuer-URL.
    *   Wallet authentifiziert sich (Signieren einer Challenge mit Private Key).
    *   Wallet speichert erhaltenen SD-JWT und alle Disclosures lokal (z. B. in einer JSON-Datei `wallet.json`).
    *   *UI:* Schöner Ladebalken während des Downloads.
3.  **Presentation (Senden):**
    *   User wählt Verifier-URL.
    *   Verifier sendet Challenge (`nonce`).
    *   **Selektive Auswahl (WICHTIG):** Terminal zeigt Liste der Claims (z. B. "Alter", "Name"). User wählt mittels Checkbox-Interface (via `rich` oder `inquirer`), welche er offenlegen will.
    *   Wallet sucht passende Disclosures heraus.
    *   Wallet erstellt **KB-JWT** (signiert `nonce` + `aud` + SD-JWT Hash mit Holder Private Key).
    *   Payload an Verifier senden: `SD-JWT` + `ausgewählte Disclosures` + `KB-JWT`.

---

### Komponente C: Der Verifier (Server)
**Rolle:** Prüft Signaturen, berechnet Hashes neu, validiert Key Binding.
**Tech Stack:** Python Flask.

#### Endpunkte (REST API):
1.  **GET** `/challenge`
    *   Generiert und speichert eine zufällige Nonce.
2.  **POST** `/verify` (OID4VP light)
    *   **Input:** SD-JWT String, Array von Disclosures, KB-JWT.
    *   **Prozess:**
        1.  **Issuer-Check:** Validierung der Signatur des SD-JWT mittels Issuer Public Key.
        2.  **Disclosure-Check:** Hashen der empfangenen Disclosures und Abgleich, ob diese Hashes im `_sd` Array des SD-JWTs enthalten sind.
        3.  **Holder-Binding-Check:** Prüfen, ob der KB-JWT mit dem Key signiert wurde, der im `cnf`-Feld des SD-JWTs steht. Prüfen der Nonce.
    *   **Output:** `{"valid": true/false, "extracted_data": {...}}`.

#### Terminal Output:
*   Anzeige der entschlüsselten Daten in einer Tabelle (nur die Claims, die der User freigegeben hat).
*   Warnmeldung in Rot, falls Signatur ungültig.

---

## 4. Infrastruktur & Sicherheit (PoC Constraints)

### 4.1 Kommunikation (HTTPS)
Da Issuer, Wallet und Verifier auf separaten Computern laufen, ist unverschlüsseltes HTTP ein Sicherheitsrisiko und bricht OID4VC-Standards.
*   **Domain-Validierung:** Nutzung von `certbot` mit dem Cloudflare DNS Plugin (`certbot-dns-cloudflare`), um Let's Encrypt Zertifikate für die Flask-Server zu generieren.
*   **Flask Setup:** Die Server müssen mit SSL-Kontext gestartet werden:
    ```python
    app.run(ssl_context=('fullchain.pem', 'privkey.pem'), host='0.0.0.0', port=443)
    ```

### 4.2 Datenfluss
1.  **Issuer -> Wallet:** JSON Response (SD-JWT + Alle Disclosures).
2.  **Wallet -> Verifier:** Kombinierter String oder JSON (SD-JWT + Selektierte Disclosures + KB-JWT). Format: `<SD-JWT>~<Disclosure1>~<Disclosure2>~<KB-JWT>`.

---

## 5. Implementierungs-Schritte für das LLM

Nutze den folgenden Prompt-Aufbau, um den Code generieren zu lassen:

### Schritt 1: Shared Library
*"Generiere eine Python-Datei `sd_jwt_utils.py`. Sie muss Funktionen enthalten für: 1. Ed25519 Key-Generierung. 2. Erstellen von Salted Disclosures (`[salt, key, value]`). 3. Hashen von Disclosures (SHA-256). 4. Validieren von SD-JWTs (Re-Hashing und Signaturprüfung). Nutze die Bibliotheken `jwcrypto` oder `cryptography`."*

### Schritt 2: Issuer Server
*"Erstelle einen Flask-Server `issuer.py` mit Terminal-UI (`rich`). Er muss Endpunkte für `.well-known` Metadata und Issuance bereitstellen. Er nutzt `sd_jwt_utils.py`, um Credentials zu signieren. Stelle sicher, dass er über HTTPS läuft (Dummy-Pfade für Zertifikate)."*

### Schritt 3: Wallet App
*"Erstelle eine Terminal-App `wallet.py` mit `rich`. Features: 1. Generiere/Lade User-Key. 2. Frage Credential vom Issuer an. 3. Interaktives Menü: Zeige Claims an und lass den User wählen, welche gesendet werden (Space zum Auswählen). 4. Sende SD-JWT + Disclosures + KB-JWT an den Verifier."*

### Schritt 4: Verifier Server
*"Erstelle `verifier.py` mit Flask. Er muss eine Nonce generieren und den `/verify` Endpunkt bereitstellen. Er muss validieren: Issuer-Signatur, Übereinstimmung der Disclosure-Hashes und die Key-Binding-Signatur (KB-JWT). Zeige das Ergebnis als `rich` Tabelle im Terminal an."*

---

## 6. Wichtige Standards & Referenzen (für das LLM Kontext)
*   **SD-JWT Format:** Payload muss `_sd` Array enthalten. Disclosures sind separat.
*   **Holder Binding:** Das SD-JWT muss einen `cnf` (Confirmation) Claim enthalten, der den Public Key des Holders (Ed25519) beinhaltet.
*   **Decoy Hashes:** (Optional für PoC) Erwähne, dass im `_sd` Array theoretisch Fake-Hashes sein könnten, um die Anzahl der Claims zu verschleiern.

---

## Version 2.0 - Stand: November 4, 2025

Ich habe deine vier Anforderungen wie folgt integriert:
1.  **Revocation:** Nutzung einer *Bitstring Status List* (simuliert), die vom Verifier geprüft wird,.
2.  **Flow:** Wechsel auf *Pre-Authorized Code Flow* (Code-Eingabe statt Login).
3.  **UX:** ASCII QR-Codes im Terminal für den Start von Sessions (Offer & Request) [User Request].
4.  **Daten-Simulation:** Der Issuer nutzt eine JSON-Datei (`citizen_db.json`) als "Datenquelle" für den Ausweis, und die Wallet speichert ihren "Bestand" ebenfalls in einem JSON (`wallet_store.json`), um die Persistenz zu simulieren.

***

# System-Blueprint: SD-JWT VC Terminal PoC (Python)

Dieser Plan instruiert ein LLM, ein vollständiges **Selective Disclosure Verifiable Credential System** zu erstellen. Das System besteht aus drei getrennten Python-Applikationen (Issuer, Wallet, Verifier), die über HTTPS kommunizieren und im Terminal laufen.

## 1. Technische Rahmenbedingungen

*   **Sprache:** Python 3.10+
*   **Architektur:** 3 separate Komponenten (Issuer, Wallet, Verifier).
*   **Netzwerk:** HTTPS erforderlich (Flask mit SSL-Kontext). Zertifikate via Cloudflare DNS ACME (simuliert durch lokale Pfade zu `.pem` Dateien).
*   **Kryptografie:**
    *   Signatur: `Ed25519` (via `cryptography` oder `jwcrypto`).
    *   Hashing: `SHA-256`.
    *   Format: SD-JWT (IETF Draft) mit `_sd` Claims,.
*   **UI:** Terminal User Interface (TUI) mit `rich` (für Farben, Tabellen) und `segno` (für ASCII QR-Codes).

---

## 2. Datenhaltung (JSON-Simulation)

Um eine echte Datenbank und Secure Storage zu simulieren, nutzen wir einfache JSON-Dateien.

### 2.1 Issuer: `citizen_db.json` (Quelle der Wahrheit)
Der Issuer liest die Daten für den Ausweis aus dieser Datei, anstatt sie live abzufragen. Dies simuliert das Melderegister.
```json
{
  "1234-CODE": {
    "given_name": "Erika",
    "family_name": "Mustermann",
    "birthdate": "1990-01-01",
    "address": "Musterstraße 1, Berlin",
    "is_over_18": true,
    "status_index": 0
  }
}
```

### 2.2 Wallet: `wallet_store.json` (Tresor)
Die Wallet speichert erhaltene Credentials und Schlüsselmaterial hier.
```json
{
  "keys": {"private": "...", "public": "..."},
  "credentials": [
    {
      "iss": "https://issuer.local",
      "sd_jwt": "eyJh...",
      "disclosures": ["...", "..."],
      "timestamp": "2023-10-27..."
    }
  ]
}
```

---

## 3. Komponente A: Der Issuer (Behörde)

**Features:** Pre-Authorized Code Flow, Bitstring Status List, ASCII QR-Code Offer.

### Workflow & Endpunkte
1.  **Start:** Beim Start lädt der Server `citizen_db.json` und generiert eine **Bitstring Status List** (eine komprimierte Liste von 0 und 1). `0` = Gültig, `1` = Widerrufen,.
2.  **Terminal Befehl `offer <user_code>`:**
    *   Der Admin gibt im Terminal `offer 1234-CODE` ein.
    *   Der Server generiert eine `credential_offer_uri` (Deep Link Schema `openid-credential-offer://...`).
    *   **Output:** Die URI wird als **ASCII QR-Code** im Terminal angezeigt (via `segno.print_ascii(uri)`), damit der User (visuell) "scannen" kann. Zusätzlich wird die URL als Text angezeigt.

### API Endpunkte (Flask)
*   `GET /.well-known/openid-credential-issuer`: Metadaten.
*   `POST /token`: Akzeptiert den `pre-authorized_code` (den Code aus der DB) und gibt ein Access Token zurück.
*   `POST /credential`:
    *   Prüft Access Token und Proof-of-Possession (Signatur über Nonce).
    *   Lädt Daten aus `citizen_db.json`.
    *   Erstellt **Salted Disclosures** für sensitive Felder (Name, Geburtsdatum),.
    *   Fügt den Claim `status` hinzu: `{"status_list": {"idx": 0, "uri": "https://issuer/status"}}`.
    *   Signiert SD-JWT.
*   `GET /status`: Gibt die aktuelle (gzip-komprimierte) Bitstring Status List zurück.

### Terminal Befehl `revoke <index>`
*   Setzt das Bit an Stelle `<index>` in der Statusliste auf `1`. Ab diesem Moment müssen Verifier den Ausweis ablehnen.

---

## 4. Komponente B: Die Wallet (Bürger)

**Features:** Key-Management, Selektive Auswahl, Speichern in JSON.

### Workflow
1.  **Setup:** Beim Start prüft/erstellt `wallet_store.json` und generiert ein Ed25519 Keypair, falls keines existiert.
2.  **Issuance (Ausweis holen):**
    *   User kopiert die URL (vom Issuer QR-Code) oder gibt sie ein.
    *   User gibt den **Pre-Authorized Code** (z. B. "1234-CODE") ein, der ihm "out-of-band" (simuliert) gegeben wurde.
    *   Wallet authentifiziert sich beim Issuer, lädt den SD-JWT + Disclosures und speichert alles in `wallet_store.json`.
3.  **Presentation (Ausweis zeigen):**
    *   User kopiert die Request-URL vom Verifier (oder "scannt" den ASCII QR).
    *   **Selektive Auswahl (TUI):** Das Terminal zeigt eine Checkbox-Liste der verfügbaren Claims (Name, Alter, etc.).
    *   Der User wählt mit [LEERTASTE] aus, was er zeigen will.
    *   Wallet sucht die passenden Disclosures.
    *   Wallet erstellt **Key Binding JWT** (signiert die Nonce des Verifiers).
    *   Sendet Paket an Verifier.

---

## 5. Komponente C: Der Verifier (Türsteher)

**Features:** SD-JWT Validierung, Status-Prüfung, ASCII QR Request.

### Workflow & Endpunkte
1.  **Terminal Befehl `request`:**
    *   Erstellt eine Session mit einer zufälligen `nonce` und `state`.
    *   Generiert einen `openid4vp://` Request Link.
    *   Zeigt diesen Link als **ASCII QR-Code** im Terminal an [User Request].
2.  **POST /verify:**
    *   Empfängt SD-JWT + Disclosures + KB-JWT.
    *   **Schritt 1 (Krypto):** Prüft Signatur des Issuers und Signatur des Holders (KB-JWT).
    *   **Schritt 2 (Disclosures):** Hasht die empfangenen Disclosures und prüft, ob sie im SD-JWT (`_sd` Array) enthalten sind.
    *   **Schritt 3 (Status/Revocation):**
        *   Liest den `status`-Claim aus dem SD-JWT.
        *   Lädt die Status-Liste vom Issuer (`GET /status`).
        *   Prüft, ob das Bit am angegebenen Index `0` ist. Wenn `1`, wird der Ausweis als **"WIDERRUFEN"** abgelehnt,.
3.  **Output:**
    *   Zeigt eine grüne Tabelle mit den validierten Daten (nur die selektierten Felder).
    *   Zeigt eine rote Warnung, falls Signaturen falsch sind oder der Status "Revoked" ist.

---

## 6. Schritt-für-Schritt Implementierungsplan (Prompt für LLM)

Nutze den folgenden Prompt, um den Code generieren zu lassen.

### Phase 1: Shared Utilities (`sd_jwt_utils.py`)
*   Implementiere Funktionen für Ed25519 KeyGen.
*   Funktion `create_disclosure(salt, key, value)` -> gibt `[digest, raw_disclosure_string]` zurück.
*   Funktion `create_sd_jwt(claims, issuer_key)` -> erstellt signierten Token mit `_sd` Array.
*   Funktion `create_status_list(size)` und `get_status(list, index)`.

### Phase 2: Issuer (`issuer.py`)
*   Flask Server mit HTTPS Context.
*   Lade `citizen_db.json`.
*   Implementiere `/credential` Endpunkt für Pre-Authorized Code Flow.
*   Implementiere `/status` Endpunkt.
*   Nutze `segno` Library, um beim Start oder auf Befehl einen QR-Code für das Credential Offer im Terminal zu zeichnen.

### Phase 3: Wallet (`wallet.py`)
*   Terminal App (Endlosschleife mit Menü).
*   Lade/Speichere `wallet_store.json`.
*   Flow "Receive Credential": Code eingeben -> Token holen -> Credential speichern.
*   Flow "Present Credential": Request URL parsen -> Claims auswählen (UI) -> KB-JWT erstellen -> Senden.

### Phase 4: Verifier (`verifier.py`)
*   Flask Server.
*   Route `/verify`: Empfängt Presentation.
*   Logik: SD-JWT Signatur prüfen -> Disclosures hashen & abgleichen -> **Status List vom Issuer holen und Bit prüfen**.
*   Zeige Ergebnis als `rich.table` im Terminal.

---

## 7. Zusammenfassung der Standards (Für den Kontext des LLMs)
*   **SD-JWT:** Hashes kommen in `_sd` Array. Plaintext Disclosures reisen separat,.
*   **Key Binding:** Der Holder signiert die `nonce` des Verifiers mit seinem Private Key. Der Public Key des Holders muss im SD-JWT (Claim `cnf`) stehen.
*   **Revocation:** Bitstring Status List ist eine datenschutzfreundliche Methode. Der Verifier lädt die ganze Liste, sieht aber nur Nullen und Einsen, ohne zu wissen, wer wer ist,.


## Version 3.0 - Stand: November 5, 2025

Das ist eine hervorragende Idee. Für einen universitären Proof of Concept (PoC) ist die **Nachvollziehbarkeit (Observability)** oft wichtiger als die reine Funktion. Da SD-JWT komplexe kryptografische Schritte beinhaltet (Hashing, Salting, Binding), sollten diese auf den Terminals "sichtbar" gemacht werden, anstatt im Hintergrund zu verschwinden.

Wir können dies als **"Live-Inspection-Mode"** oder **"Verbose Logging"** in den Plan integrieren. Dabei nutzen wir die Bibliothek `rich`, um technische Details visuell vom normalen Benutzerfluss zu trennen (z. B. gelbe Panels für "Traffic", blaue für "Kryptografie").

Hier ist, wie wir das in den Plan für das LLM aufnehmen, basierend auf den technischen Prozessen in deinen Quellen:

---

### Konzept: Der "Inspection Monitor"

Jede Komponente (Issuer, Wallet, Verifier) bekommt einen zusätzlichen Output-Modus, der die "Black Box" öffnet.

#### 1. Auf dem Issuer-Terminal: Die Transformation sichtbar machen
Normalerweise sieht der Issuer nur "Ausweis erstellt". Wir ändern das, damit man sieht, wie aus Daten kryptografische Hashes werden.
*   **Was wird angezeigt:**
    *   **Schritt 1 (Raw Data):** Zeige den Datensatz aus `citizen_db.json` (z. B. `Geburtsdatum: 1990-01-01`).
    *   **Schritt 2 (Salting):** Zeige das generierte Disclosure-Array: `["zufallssalt123", "birthdate", "1990-01-01"]`.
    *   **Schritt 3 (Hashing):** Zeige den resultierenden Hash: `uH4sI...` (Base64URL).
    *   **Schritt 4 (Token-Bau):** Zeige den finalen Payload des SD-JWT, wo nur noch die Hashes im `_sd`-Array stehen, aber die Klardaten verschwunden sind.

#### 2. Auf dem Wallet-Terminal: Den Datenaustausch (Traffic) sichtbar machen
Hier visualisieren wir die Protokolle OID4VCI (Erhalt) und OID4VP (Präsentation).
*   **Was wird angezeigt:**
    *   **Incoming (VCI):** Zeige das empfangene JSON-Paket vom Issuer. Visualisiere, dass der SD-JWT (signiert) und die Disclosures (Klartext) getrennt ankommen.
    *   **Storage:** Zeige kurz, wie es in der `wallet_store.json` abgelegt wird.
    *   **Outgoing (VP):** Wenn der User Claims auswählt, zeige live:
        *   "Selektiere Disclosures für: Name, Alter..."
        *   **Generierung KB-JWT:** Zeige die Nonce vom Verifier und wie die Wallet sie mit ihrem privaten Schlüssel signiert (Besitznachweis).
        *   **Das Paket:** Zeige den finalen String, der über HTTPS gesendet wird: `<SD-JWT>~<Disclosure1>~<Disclosure2>~<KB-JWT>`.

#### 3. Auf dem Verifier-Terminal: Die Mathematik sichtbar machen
Der Verifier ist oft eine "Black Box", die nur Ja/Nein sagt. Wir wollen sehen, *warum* er Ja sagt.
*   **Was wird angezeigt:**
    *   **Empfang:** Zeige die einkommenden Teile (Token, Disclosures, KB-JWT).
    *   **Hash-Check (Live-Rechnung):**
        *   Input: Empfangene Disclosure "Alter".
        *   Berechnung: Hash(Disclosure).
        *   Vergleich: "Suche diesen Hash im SD-JWT..." -> **MATCH/NO MATCH**.
    *   **Status-Check:** Zeige den Download der Bitstring-Liste und das Prüfen des spezifischen Bits (z. B. "Prüfe Bit an Position 5... Wert ist 0 -> GÜLTIG").

---

### Aktualisierung des LLM-Prompts

Füge diesen Abschnitt als **Punkt 5** oder als Erweiterung der Komponenten-Beschreibung in das Markdown-Dokument ein, das du generieren lässt:

***

#### 5. Anforderung: "Live-Inspection" Logging (Observability)
Da es sich um einen PoC handelt, ist es entscheidend, dass wir auf jedem Computer im Terminal genau sehen, was im Hintergrund passiert. Implementiere ein `LogManager`-Modul mit `rich`, das folgende "Events" visuell hervorgehoben (z. B. in farbigen Panels) ausgibt:

1.  **Issuer-Logs (Crypto-Insight):**
    *   Logge vor dem Signieren jedes generierte Salt und die daraus resultierende Disclosure (Klartext vs. Hash).
    *   Zeige den Unterschied zwischen dem `payload` (mit Hashes) und den `disclosures` (Klartext).

2.  **Wallet-Logs (Traffic-Monitor):**
    *   Zeige bei jedem HTTP-Request/Response den vollen JSON-Body an (formatiert).
    *   Zeige bei der Präsentation genau, welche Disclosures aus dem Speicher geholt wurden und welche *nicht* gesendet werden (Privacy-Demonstration).
    *   Zeige den Inhalt des Key-Binding-JWTs (signierte Nonce), bevor er verschickt wird.

3.  **Verifier-Logs (Verification-Logic):**
    *   Gib eine "Checkliste" im Terminal aus, die live abgehakt wird:
        *   [x] Issuer Signatur gültig (Ed25519)
        *   [x] KB-JWT Signatur gültig (Proof of Possession)
        *   [x] Disclosure-Hash [xy...] gefunden in SD-JWT
        *   [x] Status-Bit geprüft (Index 0 = OK)

**UX-Hinweis:** Nutze `rich.panel.Panel` mit Titeln wie "OUTGOING TRAFFIC" oder "CRYPTO OPERATION", um dies vom normalen User-Input (Menüs) abzuheben.

***

### Zusammenfassung der Wirkung
Mit dieser Ergänzung wird dein PoC nicht nur zeigen, *dass* es funktioniert, sondern auch *wie*.
*   Du siehst auf dem **Issuer-Screen**: "Aha, hier werden meine Daten gesalzen."
*   Du siehst auf dem **Wallet-Screen**: "Ich sende wirklich nur das Alter, die Adresse bleibt hier.",.
*   Du siehst auf dem **Verifier-Screen**: "Die Mathematik stimmt, der Hash passt."

Das macht die Präsentation extrem stark, weil du auf die Monitore zeigen und die Konzepte (Data Minimization, Binding, Hashing) live erklären kannst.

## Version 4.0 - Stand: November 6, 2025

Das ist eine sehr gute Frage. Wenn man ein System von Grund auf als Proof of Concept (PoC) baut – besonders in einem universitären Kontext – liegen die Tücken oft im Detail. Basierend auf den Quellen und typischen Fallstricken bei solchen Implementierungen gibt es noch **fünf wesentliche Bereiche**, die du dir anschauen oder direkt in den Plan für das LLM aufnehmen solltest, um das Projekt robuster und beeindruckender zu machen.

Hier sind die Punkte, sortiert nach Kategorien:

### 1. Einhaltung der Standards (Privacy & Security)

**A. Decoy Hashes (Täuschungs-Hashes) gegen "Profiling"**
Das ist ein technisches Detail, das bei SD-JWT oft vergessen wird, aber den Unterschied zwischen "gut gemeint" und "echter Privacy" ausmacht.
*   *Problem:* Wenn dein Ausweis immer genau 5 Hashes im `_sd` Array hat, kann ein Verifier erraten, um welchen Ausweistyp es sich handelt (Fingerprinting), selbst wenn er keine Inhalte sieht.
*   *Lösung:* Der Standard erlaubt das Einfügen von **Decoy Hashes** (gefälschte Hashes ohne Disclosure) in den Token,.
*   *Umsetzung:* Lass den Issuer zufällig 1–3 Fake-Hashes in das Array mischen. Das Wallet kann diese nicht entschlüsseln und sendet sie einfach nicht mit. Das zeigt tiefes Verständnis des Standards.

**B. Replay-Schutz durch "Nonce-Verwaltung"**
Du hast Key-Binding (KB-JWT) geplant, aber der Teufel steckt im Detail der `nonce`.
*   *Problem:* Wenn ein Angreifer die Präsentation (den Datenverkehr) abfängt, könnte er sie später erneut an den Verifier senden.
*   *Lösung:* Der Verifier muss sich merken: "Ich habe Nonce `XYZ` an User A gesendet". Wenn die Antwort kommt, muss er prüfen: Passt die Nonce? Und danach muss er die Nonce **sofort löschen** (One-Time-Use),. Wenn der Verifier "stateless" ist (nichts speichert), ist das System unsicher.

### 2. Usability & User Experience (UX)

**A. Der "Consent Screen" (Zustimmung)**
Laut Quellen ist die explizite Zustimmung des Nutzers *vor* dem Senden der Daten der wichtigste Schritt,.
*   *Umsetzung:* Bevor das Wallet die Daten an den Verifier sendet, sollte im Terminal eine klare Zusammenfassung erscheinen:
    > "ACHTUNG: `Shop.com` fragt nach `Alter`. `Adresse` wird NICHT gesendet. [J]a / [N]ein?"
    Das visualisiert das Prinzip der "Selective Disclosure" perfekt für die Zuschauer.

**B. Short-Links statt riesiger URLs**
Du willst ASCII QR-Codes nutzen. Das ist optisch toll. Aber da die Computer getrennt sind, kannst du den QR-Code im Terminal des einen Computers nicht scannen, um die Daten auf den anderen zu bekommen (außer du nutzt echte Webcams und eine QR-Lib).
*   *Vorschlag:* Implementiere zusätzlich einen **Short-Code-Mechanismus**.
    *   Der Verifier zeigt QR-Code und Text: `Link: https://verifier.com/request?id=very-long-string`.
    *   Dazu ein Short-Code: `Session-ID: 4921`.
    *   Im Wallet tippt der User nur `4921` ein, und das Wallet holt sich die lange URL im Hintergrund. Das erhöht die Usability im Terminal-Setup massiv.

### 3. Fehler-Prävention (Deployment)

**Zeitsynchronisation (`nbf` & `exp`)**
Ein klassischer Fehler bei verteilten Systemen (3 separate Computer): Die Uhren gehen nicht synchron.
*   *Problem:* Der Issuer erstellt den Token um 10:00:00 Uhr (`nbf`: not before 10:00). Der Computer des Verifiers glaubt aber, es sei 09:59:55 Uhr. Er wird den Token als "noch nicht gültig" ablehnen,.
*   *Lösung:* Füge beim Verifizieren im Code einen `leeway` (Toleranzbereich) von ca. 30–60 Sekunden ein. Das verhindert den frustrierenden "Vorführeffekt", wenn die Demo live läuft.

### 4. "Trust Registry" (Wie vertraut man dem Issuer?)

In deinem aktuellen Plan prüft der Verifier die Signatur des Issuers. Aber woher kennt er dessen Public Key?
*   *Standard:* Normalerweise über DIDs (Decentralized Identifiers) oder X.509 Zertifikatsketten,.
*   *PoC-Lösung:* Erstelle eine kleine statische JSON-Datei beim Verifier namens `trusted_issuers.json`.
    *   Inhalt: `{"https://issuer.local": "PUBLIC_KEY_STRING"}`.
    *   Das simuliert eine **Trust Registry**. Wenn der Verifier einen Token von "issuer.local" bekommt, schaut er in dieser Datei nach. Das ist realistischer als den Key hardcodiert im Python-Code zu haben.

### 5. Präsentationsfaktor: DCQL (Der "Blick in die Zukunft")

Die Quellen erwähnen, dass sich der Standard für die Anfrage von Daten gerade von "Presentation Exchange" zu **DCQL (Digital Credentials Query Language)** verschiebt,.
*   *Idee:* Auch wenn du technisch vielleicht nur eine einfache Liste abfragst, könntest du im Terminal des Verifiers die Anfrage als DCQL-Query ausgeben.
    *   Beispiel Output: `Querying Wallet: credentials.where(claim.age > 18)`.
    *   Das zeigt, dass du dich mit den allerneuesten Drafts (Stand Ende 2024/2025 laut Quellen) beschäftigt hast.

---

### Erweiterung für den Prompt

Hier ist der Textbaustein, den du noch zu deinem LLM-Plan hinzufügen kannst, um diese Punkte abzudecken:

***

#### 6. Ergänzende Anforderungen für Robustheit und "Wow-Effekt"

Bitte berücksichtige bei der Code-Generierung folgende Details:

1.  **Trust Registry Simulation:**
    *   Der Verifier soll die Public Keys der vertrauenswürdigen Issuer nicht im Code hardcoden, sondern aus einer Datei `trusted_registry.json` laden. Das simuliert eine echte PKI/DID-Infrastruktur.

2.  **Clock Skew Toleranz:**
    *   Setze bei der Validierung von `nbf` (not before) und `exp` (expiration) in der `sd_jwt_utils.py` einen Zeit-Puffer (Leeway) von 60 Sekunden, um Probleme mit nicht synchronisierten Systemuhren der drei Computer zu vermeiden.

3.  **Privacy Feature "Decoy Hashes":**
    *   Der Issuer soll beim Erstellen des SD-JWTs (`create_sd_jwt`) optional 1-2 zufällige "Decoy Hashes" (Hashes von Zufallswerten ohne Disclosure) in das `_sd` Array mischen. Dies demonstriert Schutz gegen Profiling.

4.  **Usability Fallback (Short-Codes):**
    *   Da wir im Terminal keine QR-Codes scannen können, sollen Issuer und Verifier zusätzlich zur langen URL eine 4-stellige **Session-ID** generieren und anzeigen (z. B. "Enter Code 4821 in Wallet").
    *   Die Wallet-App muss erlauben, entweder die volle URL oder diese Session-ID einzugeben (bei ID baut die Wallet die URL zur lokalen IP zusammen).

***

Mit diesen Ergänzungen deckst du **Sicherheit** (Replay/Trust), **Usability** (Short-Codes/Time-Sync) und **Standard-Tiefe** (Decoys/DCQL) ab.

## Version 5.0 - Stand: November 7, 2025

Das ist eine sehr sinnvolle Ergänzung. Für einen universitären Proof of Concept (PoC) ist ein persistenter, detaillierter Log-Ordner Gold wert, um beim Debuggen oder bei der Präsentation genau nachvollziehen zu können, warum etwas funktioniert (oder nicht).

Basierend auf den technischen Details aus deinen neuen Quellen (insbesondere zu den kryptografischen Transformationen bei SD-JWT und den OID4VC-Protokollen) habe ich die Anforderungen für das Logging-System spezifiziert.

Hier ist das Update für deinen System-Blueprint, das du dem LLM geben kannst.

***

### Erweiterung: Das "Deep-Trace" Logging-System

Wir fügen eine neue Anforderung für ein Dateisystem-basiertes Logging hinzu. Ziel ist es, nach jedem Durchlauf eine "Black Box"-Datei zu haben, die jeden kryptografischen Schritt enthüllt.

#### 1. Dateistruktur & Verhalten
*   **Ordner:** Erstelle im Root-Verzeichnis einen Ordner `/logs`.
*   **Dateinamen:** Jede Komponente schreibt in ihre eigene Datei: `issuer_debug.log`, `wallet_debug.log`, `verifier_debug.log`.
*   **Modus:** Die Dateien müssen bei jedem Neustart des Scripts **überschrieben** werden (`mode='w'`), damit immer nur der letzte Lauf enthalten ist (kein "Appending" alter Runs).
*   **Format:** `[TIMESTAMP] [LEVEL] [COMPONENT] :: Message` + (Optional) `JSON Dump`.

#### 2. Inhaltliche Anforderungen an die Logs (Nach Komponenten)

Das LLM soll sicherstellen, dass folgende spezifische Datenpunkte basierend auf den Standards geloggt werden:

**A. Issuer Logs (Fokus: Kryptografische Transformation)**
*   **Salting Prozess:** Logge für jeden Claim das generierte Salt.
    *   *Format:* `DEBUG: Salt generiert für 'birthdate': <random_string>`
*   **Disclosure Erstellung:** Logge das Array *vor* dem Hashing.
    *   *Format:* `DEBUG: Raw Disclosure: ["<salt>", "birthdate", "1990-01-01"]`
*   **Hashing:** Logge den resultierenden Hash.
    *   *Format:* `DEBUG: Hash (SHA-256): <hash_value>`
*   **Token Struktur:** Speichere den kompletten Payload des SD-JWTs (mit den `_sd` Hashes, aber ohne die Klartext-Werte) als JSON-Dump im Log.

**B. Wallet Logs (Fokus: OID4VCI & OID4VP Protokolle)**
*   **Protokoll-Handshake:**
    *   Logge den empfangenen `Credential Offer` URI und das geparste JSON.
    *   Logge den `Token Request` inklusive des `c_nonce` Proof-of-Possession JWTs (entscheidend für Sicherheit).
*   **Presentation Selection:**
    *   Logge die `input_descriptors` oder `dcql_query` vom Verifier (was wird verlangt?).
    *   Logge die Entscheidung des Users: "User selected: ['age_over_18', 'given_name']".
*   **Key Binding:**
    *   Logge die `nonce`, die vom Verifier kam.
    *   Logge den erstellten `KB-JWT` Header und Payload, der beweist, dass der Key dem Wallet gehört.

**C. Verifier Logs (Fokus: Validierungs-Logik)**
*   **Hash-Re-Calculation:**
    *   Logge: "Empfangene Disclosure für 'birthdate'. Berechne Hash neu..."
    *   Logge: "Berechneter Hash: <xyz> | Gefunden in SD-JWT: [JA/NEIN]".
*   **Status Check:**
    *   Logge den Abruf der Status-Liste.
    *   Logge: "Prüfe Bit an Index <x>. Wert ist <0/1>. Status: <VALID/REVOKED>".

#### 3. Implementierungs-Prompt für das LLM

Füge diesen Block in deine Anweisungen ein:

> **Zusatz-Modul: File-Logging (`logger_config.py`)**
> Erstelle ein zentrales Logging-Modul, das von allen drei Skripten importiert wird.
> 1. Es muss eine Funktion `setup_logger(name, filename)` bereitstellen.
> 2. Der Logger muss so konfiguriert sein, dass er die Datei `filename` im Ordner `logs/` bei jedem Start **überschreibt** (`filemode='w'`).
> 3. Setze das Level auf `DEBUG`.
> 4. **WICHTIG für den PoC:** Da dies eine Lernanwendung ist, sollen sensible Daten (Salts, Private Keys in Transits) *explizit* in die Logdatei geschrieben werden, damit wir den kryptografischen Prozess nachvollziehen können. (Füge im Code einen Kommentar hinzu, dass man dies in Produktion niemals tun würde).
> 5. Nutze `json.dumps(obj, indent=2)` für schöne Formatierung von Payloads in der Logdatei.

***

### Warum das auf deine Quellen passt:
*   **Nachvollziehbarkeit:** Quellen und beschreiben den komplexen Weg vom Klartext zum Hash. Ohne Logs sieht man diesen Prozess im Terminal oft nicht schnell genug. Die Datei erlaubt eine "Post-Mortem"-Analyse.
*   **Protocol Debugging:** OID4VCI und OID4VP sind komplex (Redirects, JSON-Austausch). Wenn etwas schiefgeht (z.B. "Verifier lehnt Token ab"), steht im Log genau: "Nonce mismatch" oder "Hash not found", statt nur "Error".
*   **Status List:** Da Bitstring Status Lists komprimiert sind (gzip), kannst du im Log die *dekomprimierte* Liste als String ausgeben lassen (z.B. `000000100`), um zu beweisen, dass der Index korrekt geprüft wurde.

## Version 6.0 - Stand: November 8, 2025

Ja, das können wir problemlos integrieren. Das ist für einen PoC sogar sehr wichtig, da ACME-Zertifikate (Let's Encrypt) oft Ablaufdaten haben oder bei IP-Änderungen im Uni-Netzwerk neu ausgestellt werden müssen, ohne dass man den ganzen Server-Code neu starten oder durchlaufen muss.

Da die bereitgestellten Quellen sich auf die Protokolle (SD-JWT, OID4VP, etc.) konzentrieren und nicht auf Deployment-Skripte für SSL-Zertifikate, basiert dieser spezifische technische Teil auf allgemeinem Best-Practice-Wissen zur Python-Entwicklung und `certbot` Integration.

Hier ist die Ergänzung für den System-Blueprint, die du dem LLM geben kannst.

***

### Erweiterung: Standalone TLS-Erneuerung per CLI-Argument

Wir fügen den Server-Skripten (`issuer.py` und `verifier.py`) einen Argument-Parser hinzu, der es erlaubt, **nur** den Zertifikats-Prozess auszuführen und sich danach zu beenden.

#### 1. Technische Anforderung
*   Nutze die Python-Bibliothek `argparse`.
*   Definiere ein Flag `--renew-certs`.
*   **Logik:** Wenn das Skript mit diesem Argument gestartet wird (z. B. `python issuer.py --renew-certs`), soll es:
    1.  Den Cloudflare-Certbot-Prozess via `subprocess` anstoßen.
    2.  Den Output des Certbot-Befehls live im Terminal (via `rich`) anzeigen.
    3.  Nach erfolgreicher Erneuerung das Skript **beenden** (`sys.exit(0)`), *bevor* der Flask-Server startet.
    4.  Dies verhindert Port-Konflikte (falls der Server schon läuft) und erlaubt eine gezielte Wartung.

#### 2. Update für den LLM-Prompt

Füge diesen Block zu den Instruktionen für **Phase 2 (Issuer)** und **Phase 4 (Verifier)** hinzu:

> **Zusatz-Feature: CLI-Argument für Zertifikats-Management**
> Implementiere in `issuer.py` und `verifier.py` einen `argparse` Handler.
> *   Füge das Argument `--renew-certs` hinzu.
> *   Wenn dieses Argument gesetzt ist:
>     *   Führe sofort die Funktion `generate_certificates()` aus (die den Certbot/Cloudflare Befehl kapselt).
>     *   Gib eine Erfolgsmeldung aus: "Zertifikate erfolgreich erneuert."
>     *   Beende das Programm sofort, ohne den Flask-Server zu starten (`app.run()` wird übersprungen).
> *   Dies ermöglicht dem Admin, die Zertifikate manuell zu refreshen, ohne den Server-Loop zu betreten:
>   `$ python issuer.py --renew-certs`

***

### Zusammenfassung der Architektur mit allen Änderungen

Hier ist der finale, konsolidierte Überblick über alle Komponenten, die du nun hast (basierend auf unseren Diskussionen und den Quellen):

1.  **Issuer & Verifier (Python Flask):**
    *   **Protokolle:** OID4VCI (Pre-Authorized Code Flow) und OID4VP (Presentation).
    *   **Kryptografie:** SD-JWT Signing (Ed25519) + Salting/Hashing von Claims.
    *   **Datenhaltung:** JSON-Dateien statt Datenbanken (simuliert Register und Trust Registry).
    *   **Security:** HTTPS via Cloudflare ACME (steuerbar über `--renew-certs`).
    *   **Status:** Bitstring Status List für Revocation (simuliert),.
    *   **Privacy:** Optionales Einfügen von "Decoy Hashes" (Täuschung),.

2.  **Wallet (Python Terminal Client):**
    *   **Storage:** `wallet_store.json` (lokaler Tresor).
    *   **UX:** ASCII QR-Codes und Short-Links für die Verbindung.
    *   **Binding:** Erstellt Key-Binding JWTs bei der Präsentation,.

3.  **Observability (Logging):**
    *   **Live-Inspection:** Detaillierte Logs im Terminal (`rich`) und im Ordner `/logs`, die jeden Hash-Vorgang und JSON-Payload sichtbar machen.

4.  **Deployment:**
    *   Separation auf 3 Computer, synchronisiert über NTP-Toleranz (Leeway), verbunden über echtes HTTPS.

Damit hast du einen vollständigen, akademisch anspruchsvollen Plan, der tief in die Details von SD-JWT (Quellen) und OID4VC (Quellen) eingeht, aber durch die Terminal-UI und JSON-Backends in einem Uni-Semester realisierbar bleibt.

## Version 7.0 - Stand: November 9, 2025

## Korrektur-Anforderungen für den SD-JWT PoC

Bitte passe den bestehenden Implementierungsplan basierend auf dem aktuellen Testing-Feedback wie folgt radikal an. Ignoriere vorherige Anweisungen zu SSL/HTTPS und statischen Wallet-Konfigurationen.

### 1. Netzwerkkonfiguration (HTTP Only & Domains)
*   **Protokoll:** Entferne jegliche SSL/TLS Konfiguration. Die Flask-Server (`issuer.py`, `verifier.py`) sollen als **reine HTTP-Server** laufen (`app.run(host='0.0.0.0', ...)` ohne `ssl_context`).
*   **URLs:** Setze folgende **Default-Base-URLs** fest codiert in den Code (aber überschreibbar via Environment Variable):
    *   Issuer: `http://sd-issuer.ltm-labs.de:5001`
    *   Verifier: `http://sd-verifier.ltm-labs.de:5002`
*   **Wallet:** Das Wallet benötigt keinen Server-Port, da es nur als Client agiert.

### 2. Wallet-Architektur: "Universal Wallet"
*   **Keine Start-Parameter:** Das Skript `wallet.py` darf beim Starten **keine** Argumente für Issuer- oder Verifier-URLs mehr verlangen.
*   **Dynamische Auflösung:**
    *   Wenn der User einen Short-Code oder eine URL eingibt, muss das Wallet selbst erkennen, wohin die Reise geht.
    *   *Issuance:* Das Wallet extrahiert die Issuer-URL aus dem `credential_offer`.
    *   *Presentation:* Das Wallet extrahiert die Verifier-URL und den Endpunkt aus dem `request_uri` bzw. dem Authorization Request.

### 3. UX & Short-Codes (6-Stellig)
*   **Sofortiges Menü:** Wenn die Skripte (Issuer, Verifier, Wallet) starten, muss **sofort** (automatisch) die Liste der verfügbaren Befehle und der aktuelle Status (z.B. "Server running on...") angezeigt werden. Der User soll nicht erst `help` tippen müssen.
*   **6-Digit Codes:** Erhöhe die Länge der generierten Session-IDs/Short-Codes beim Issuer und Verifier von 4 auf **6 Ziffern** (z.B. `839201`), um die Sicherheit zu erhöhen.

### 4. Zeit-Synchronisation (Leeway)
*   **Toleranz verringern:** Setze in `sd_jwt_utils.py` beim Validieren von `nbf` (not before) und `exp` (expiration) sowie beim Prüfen des `iat` (issued at) den Toleranzbereich (`leeway`) auf **20 Sekunden** (statt vorher 60). Das System soll strikter sein, aber leichte Uhren-Abweichungen der VMs tolerieren.

### Zusammenfassung der geänderten Flows

**Neuer Issuance Flow (HTTP):**
1.  Admin am Issuer tippt: `offer <user_id>`
2.  Issuer generiert Code `123456` und speichert Session in Memory.
3.  User am Wallet tippt: `receive 123456` (oder die volle URL `http://sd-issuer.ltm-labs.de:5001/offer/123456`).
4.  Wallet fragt Issuer per HTTP an `http://sd-issuer.ltm-labs.de:5001/...`.

**Neuer Presentation Flow (HTTP):**
1.  Admin am Verifier tippt: `request`
2.  Verifier generiert Code `987654` und wartet auf `http://sd-verifier.ltm-labs.de:5002/verify`.
3.  User am Wallet tippt: `present 987654` (oder die URL).
4.  Wallet sendet Daten per HTTP POST an den Verifier.
