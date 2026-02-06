Private-Public-Key: id_ed25519: 2x: 1x für issuer, 1x für wallet

Kommunikation per HTTP(S) 
python-framework: flask

wahrscheinlich keine Endpunkte auf Holder/Wallet
Verifier und Issuer bieten Endpunkte für SD-JWTs und SD-JWTs-Abfrage; Wallet dürfte in dem immer Triggerpunkt der Kommunikation sein --> keine nötigen Endpunkte

Für Demo, Grundflow:
Issuer: Python Webservice der Endpunkt für SD-JWT Bereitstellung & Public-Key zur Signaturprüfung hat

Wallet: Skript, dass Kommunikation zum SD-JWT Retrieval triggert (dabei muss Public-Key vom Issuer mitgeschickt werden für Holder-Binding-Embedding), zwischenspeichert und anschließend an Verifier schickt (+ Disclosures und Holder Binding JWT) um etwas nachzuweisen. Bei Nutzerbestätigung --> Terminal Abfrage

Verifier: Python Webservice der Endpunkt für SD-JWTs Bestätigung / Disclosure Nachweis enthält und Signatur von Issuer + Holder Binding checkt

Verifier generiert ggf. "Session"Code/URL, welche im Wallet eingelesen wird und daraufhin Kommunikation angetriggert wird

Holder Binding JWT bestehend aus nonce (kryptografisch generierte Challenge, vom Verifier), aud (Verifier-ID), iat, exp
	--> nonce muss/sollte unique sein

Schnittstellen:
- Issuer: kann Daten aus irgendeiner Quelle (z.B. Textdatei/Json/YAML) einlesen, aus welchen dann das SD_JWT generiert wird
	- 1x Endpunkt für SD_JWT
		- Parameter: Public-Key vom Wallet für Embedding in SD-JWT, (Optinal: sub/holder-ID für JWT->Wallet-Binding)
		- Response: SD_JWT, Disclosures
	- 1x Endpunkt für JWKS-Abfrage zur Signatur-Prüfung
		- Parameter: -
		- Response: JWKS
- Verifier: 
	- 1x "requestChallenge" Endpunkt für Challenge-Generierung
		- Parameter: -
		- Response: Challenge
	- 1x "verifyAttribute" Endpunkt für Nachweis und Überprüfung von Disclosure
		- Parameter: mit Private-Key signierte Challenge aus vorheriger ("requestChallenge")-Anfrage (=Holder Binding JWT), SD-JWT, Teilmenge der Disclosures --> als ein JSON zb
		- Response: Erfolgreich ja / nein


Minimal-Flow (chatgpt):
- **Verifier**: `POST /requestChallenge` → `{ session_id, nonce, requested_claims }`
- **Wallet**: holt vom **Issuer** `POST /credential` mit `{ holder_pub_jwk }` → Credential (sd_jwt + disclosures)
- **Wallet**: User bestätigt → Wallet wählt Disclosures
- **Wallet**: erstellt `holder_proof_jwt` signiert mit holder private key über `{ nonce, aud, iat, exp }`
- **Wallet → Verifier**: `POST /verifyAttribute` mit `{ session_id, sd_jwt, disclosures[], holder_proof_jwt }`
- **Verifier**: validiert alles, antwortet ok/fail + ggf. extrahierte Claims

zuerst mal Issuer und Wallet --> Tobi: Issuer, Marvin: Wallet 
