# Come estendere l'analisi di SpamBox

L'architettura separa nettamente **recupero messaggio** (`spambox/worker/imap_client.py`,
`mime_parser.py`), **analizzatori** (`spambox/worker/analyzers/`) e **scoring**
(`spambox/worker/verdict.py`). Aggiungere un nuovo controllo significa quasi
sempre: scrivere un nuovo analizzatore + aggiungere una componente di score.

## Aggiungere ClamAV (scansione allegati locale)

1. Creare `spambox/worker/analyzers/clamav.py` con una funzione
   `scan_attachment(payload: bytes) -> dict` che parla con `clamd` (via socket
   Unix o TCP, es. libreria `clamd` o chiamata diretta al protocollo INSTREAM).
2. In `spambox/worker/main.py`, dentro `process_one_message`, richiamare la
   funzione per ogni `Attachment` estratto da `parse_message` (i byte grezzi
   dell'allegato vanno recuperati ri-decodificando la parte MIME, oppure
   estendendo `Attachment` per contenere anche il payload).
3. Aggiungere una componente `_clamav_component` in `verdict.py` e un peso
   dedicato in `config.yaml` (sezione `scoring`).
4. Aggiungere il risultato al dizionario `log_entry` in `main.py` così da
   comparire sia nel JSONL sia (con una colonna aggiuntiva) nella UI.

## Aggiungere altri feed di reputazione (OpenPhish, PhishTank, AbuseIPDB)

URLhaus (`spambox/worker/analyzers/urlhaus.py`) e il controllo età dominio via
RDAP (`spambox/worker/analyzers/domain_age.py`) sono già implementati e
integrati nello scoring — vedi il README per come configurarli. Per
aggiungerne altri (OpenPhish, PhishTank, AbuseIPDB), che tipicamente
espongono liste di IOC scaricabili periodicamente (CSV/JSON) invece di
un'API di lookup diretta come URLhaus, il pattern consigliato è:

1. Un modulo `spambox/worker/analyzers/threat_feeds.py` che carica/aggiorna
   una cache locale (es. SQLite o file) dei feed, con un refresh separato
   (altro timer systemd) per non rallentare ogni ciclo di polling.
2. Una funzione `check_url(url) -> dict` / `check_ip(ip) -> dict` che
   interroga la cache locale.
3. Integrare il risultato nello scoring come per URLhaus/VirusTotal (nuova
   componente in `verdict.py` + peso dedicato in `config.yaml`).

## Integrazione futura con MISP

Non prevista nella prima versione. Quando necessario, aggiungere un modulo
`spambox/worker/analyzers/misp.py` che usa `pymisp` per interrogare/pubblicare
IOC, mantenendo lo stesso pattern: input (URL/hash/dominio) -> risultato
normalizzato -> componente di score.

## Regola generale per non rompere nulla

Ogni analizzatore deve:
- non sollevare eccezioni verso il chiamante (gestire timeout/errori di rete
  internamente e restituire un risultato con `"available": False` o simile);
- essere disattivabile da configurazione;
- restituire dati serializzabili in JSON (verranno scritti sia su SQLite che
  su file JSONL).
