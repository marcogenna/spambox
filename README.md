# SpamBox

Sistema automatico per l'analisi di email sospette (phishing/spam) inoltrate
dagli utenti a una mailbox dedicata. Un **worker** Python scarica via IMAP i
messaggi non ancora elaborati e li analizza incrociando più segnali: Rspamd,
VirusTotal, URLhaus, Google Safe Browsing, età di registrazione del dominio
(RDAP), rilevamento di domini lookalike/typosquatting, impersonificazione di
brand noti (corrieri, banche, utility...), discrepanza From/Reply-To, e
controlli SPF/DKIM/DMARC. Risponde in italiano via SMTP a chi ha inoltrato
l'email con un verdetto comprensibile anche da chi non è tecnico, e registra
tutto in modo strutturato (SQLite + JSONL). Una piccola **interfaccia web**
(FastAPI) serve per gestire i domini legittimi da proteggere, la whitelist
dei mittenti autorizzati, e consultare lo storico analisi.

Non è un server di posta completo: è un worker isolato che controlla una sola
casella e risponde, affiancato da una interfaccia di amministrazione.

## Indice

- [Architettura](#architettura)
- [Requisiti](#requisiti)
- [Installazione](#installazione)
- [Configurazione](#configurazione)
- [Database](#database)
- [Esecuzione manuale (test)](#esecuzione-manuale-test)
- [Esecuzione come servizio (systemd)](#esecuzione-come-servizio-systemd)
- [Gestione dei domini protetti](#gestione-dei-domini-protetti)
- [Domini autorizzati a inoltrare email (whitelist mittenti)](#domini-autorizzati-a-inoltrare-email-whitelist-mittenti)
- [Pulizia della mailbox dopo l'elaborazione](#pulizia-della-mailbox-dopo-lelaborazione)
- [Consultazione dei log](#consultazione-dei-log)
- [Come funziona il rilevamento lookalike](#come-funziona-il-rilevamento-lookalike)
- [Come funziona l'integrazione VirusTotal](#come-funziona-lintegrazione-virustotal)
- [Come funziona il controllo età del dominio (RDAP)](#come-funziona-il-controllo-età-del-dominio-rdap)
- [Come funziona l'integrazione URLhaus](#come-funziona-lintegrazione-urlhaus)
- [Come funziona l'integrazione Google Safe Browsing](#come-funziona-lintegrazione-google-safe-browsing)
- [Rilevamento impersonificazione brand e Reply-To dirottato](#rilevamento-impersonificazione-brand-e-reply-to-dirottato)
- [Note sui rate-limit di VirusTotal](#note-sui-rate-limit-di-virustotal)
- [Diagnostica](#diagnostica)
- [Deployment su Raspberry Pi / DietPi](#deployment-su-raspberry-pi--dietpi)
- [Backup](#backup)
- [Sicurezza](#sicurezza)
- [Estendere il sistema](#estendere-il-sistema)
- [Contribuire](#contribuire)
- [Licenza](#licenza)

## Architettura

```
Utente --(forward)--> Mailbox dedicata (qualsiasi server IMAP/SMTP)
                            |
                            v
                    [worker systemd timer, ogni ~2 min]
                    1. IMAP: scarica UNSEEN
                    2. Parsing MIME (header, corpo, URL, allegati)
                    3. Rspamd (score/simboli)  -- via HTTP API
                    4. VirusTotal (URL + hash) -- API v3, rate-limited
                    5. Lookalike domini (vs. lista domini protetti)
                    6. SPF/DKIM/DMARC (da Authentication-Results)
                    7. Scoring -> verdetto in italiano
                    8. SMTP: invio risposta al forwarder
                    9. Log: SQLite + JSONL
                            |
                            v
                    data/spambox.db  <-- letto/scritto anche da:
                            ^
                            |
                    [interfaccia web FastAPI, servizio systemd separato]
                    - CRUD domini protetti
                    - Consultazione/filtri log
```

Worker e interfaccia web sono **due processi indipendenti** che condividono
lo stesso file SQLite (modalità WAL, sicura per letture concorrenti) e lo
stesso file di configurazione.

## Requisiti

- Linux/Debian con Python 3.10+
- Accesso IMAP a una mailbox dedicata (es. `spamreport@tuodominio.it`) —
  **qualsiasi provider/hosting con IMAP standard va bene** (Bluehost e altri
  hosting cPanel, Gmail/Google Workspace, Office 365, un server self-hosted,
  ecc.): il progetto è nato testandolo su Bluehost, ma non ne dipende in
  alcun modo
- Un relay SMTP già configurato per l'invio delle risposte (idem: qualsiasi
  server SMTP standard con autenticazione)
- Rspamd raggiungibile via HTTP (installazione locale standalone, porta
  controller di default `11334`) — opzionale ma consigliato, il sistema
  degrada correttamente se non disponibile
- Una API key di [VirusTotal](https://www.virustotal.com/) (anche il tier
  gratuito va bene, con i limiti descritti più sotto)

Librerie Python usate (vedi `requirements.txt`): `PyYAML`, `requests`,
`fastapi`, `uvicorn`, `jinja2`, `python-multipart`. Per IMAP/SMTP/MIME e per
il calcolo della distanza di Levenshtein si usano solo moduli della standard
library (`imaplib`, `smtplib`, `email`, `hashlib`, `difflib` + una piccola
implementazione pura Python della distanza di Levenshtein in
`spambox/worker/analyzers/lookalike.py`), per non introdurre dipendenze
compilate fragili da mantenere su Debian.

## Installazione

### Installazione automatica

Su Debian/DietPi/Raspberry Pi OS, `scripts/install.sh` automatizza tutti i
passaggi manuali descritti sotto (pacchetti di sistema, utente dedicato,
ambiente Python, copia dei template di configurazione, unit systemd):

```bash
git clone https://github.com/<org>/spambox.git
cd spambox
sudo ./scripts/install.sh
```

Lo script **non avvia i servizi**: al termine ti dice esattamente quali due
file compilare (`config/config.yaml` e `config/spambox.env`) prima di fare
`systemctl enable --now`. È sicuro rilanciarlo più volte: non sovrascrive
configurazioni già presenti.

### Installazione manuale

```bash
sudo useradd --system --home /opt/spambox --shell /usr/sbin/nologin spambox
sudo mkdir -p /opt/spambox
sudo chown spambox:spambox /opt/spambox
# copiare il contenuto del repository in /opt/spambox

cd /opt/spambox
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

## Configurazione

```bash
cp config/config.example.yaml config/config.yaml
cp config/spambox.env.example config/spambox.env
chmod 600 config/spambox.env
```

Modificare `config/config.yaml` con host/porte IMAP e SMTP reali, base URL di
Rspamd, domini, ecc. **Le credenziali vere (password IMAP/SMTP, API key
VirusTotal, hash password web) vanno messe in `config/spambox.env`**, mai in
`config.yaml` committato: le variabili d'ambiente hanno sempre la precedenza
sui valori nel file YAML (vedi `spambox/config.py`).

Per generare l'hash della password dell'interfaccia web:

```bash
./venv/bin/python scripts/hash_password.py
```

L'output va copiato in `SPAMBOX_WEB_PASSWORD_SHA256` dentro `config/spambox.env`.

## Database

Il database SQLite viene creato automaticamente al primo avvio (sia dal
worker che dalla webapp) nel path indicato da `storage.sqlite_path`. Per
inizializzarlo esplicitamente:

```bash
SPAMBOX_CONFIG=config/config.yaml ./venv/bin/python scripts/init_db.py
```

## Esecuzione manuale (test)

Worker (esegue un singolo ciclo di polling e termina):

```bash
SPAMBOX_CONFIG=config/config.yaml ./venv/bin/python -m spambox.worker.main
```

Interfaccia web:

```bash
SPAMBOX_CONFIG=config/config.yaml ./venv/bin/uvicorn spambox.webapp.app:app --host 127.0.0.1 --port 8088 --reload
```

poi aprire `http://127.0.0.1:8088` (richiede le credenziali HTTP Basic
configurate).

## Esecuzione come servizio (systemd)

File di unit pronti in `systemd/` (da adattare ai path reali):

```bash
sudo cp systemd/spambox-worker.service systemd/spambox-worker.timer systemd/spambox-web.service /etc/systemd/system/
sudo systemctl daemon-reload

# worker: eseguito periodicamente dal timer, non va abilitato come servizio permanente
sudo systemctl enable --now spambox-worker.timer

# interfaccia web: servizio permanente
sudo systemctl enable --now spambox-web.service
```

Verifica:

```bash
systemctl status spambox-worker.timer
journalctl -u spambox-worker.service -n 50
systemctl status spambox-web.service
```

L'interfaccia web è esposta di default solo su `127.0.0.1:8088`: va messa
dietro un reverse proxy (nginx/Apache) con HTTPS se deve essere raggiunta da
altri host, oppure lasciata raggiungibile solo in rete interna / via VPN.

## Gestione dei domini protetti

Dalla sezione **Domini protetti** dell'interfaccia web è possibile
aggiungere, modificare ed eliminare i domini legittimi dell'organizzazione
(es. `miodominio.com`). Questi domini sono la base con cui il worker confronta
il dominio del mittente di ogni email inoltrata, per rilevare tentativi di
typosquatting/lookalike (vedi sezione dedicata più sotto). Le modifiche sono
immediate: il worker legge la lista aggiornata a ogni ciclo di polling.

## Domini autorizzati a inoltrare email (whitelist mittenti)

Per evitare che chiunque possa inoltrare email alla mailbox dedicata e
consumare inutilmente le API di VirusTotal (a quota limitata) o far inviare
risposte automatiche a indirizzi arbitrari, il worker analizza **solo** i
messaggi il cui mittente ha un dominio presente nella sezione **Domini
autorizzati** dell'interfaccia web (es. `miaazienda.com`, `mia-filiale.com`
— se ne possono aggiungere altri in qualsiasi momento dalla stessa pagina,
con lo stesso pattern di CRUD dei domini protetti). Un sottodominio di un
dominio autorizzato (es. `mail.miaazienda.com`) è considerato
automaticamente autorizzato.

Le email il cui mittente non è in questa lista **non vengono analizzate e non
ricevono risposta**: vengono comunque registrate nel log con verdetto
"Ignorata" (per poterle rivedere se necessario) e poi cancellate come tutte le
altre. Se la lista è vuota, il worker registra un avviso nei log applicativi
e ignora tutte le email in arrivo — va quindi popolata subito dopo il primo
deployment.

## Pulizia della mailbox dopo l'elaborazione

La mailbox dedicata a SpamBox non viene usata come archivio: dopo ogni ciclo
di polling, il worker:

1. **cancella definitivamente** ogni email ricevuta appena elaborata (non
   viene più spostata in una cartella "Processed" come in una versione
   precedente: l'unico registro persistente è il log strutturato
   SQLite/JSONL, consultabile dall'interfaccia web);
2. **svuota completamente la cartella dei messaggi inviati** (`imap.sent_mailbox`
   in `config.yaml`, tipicamente `INBOX.Sent`), dove il server salva
   automaticamente una copia di ogni risposta inviata via SMTP autenticato.

Il nome della cartella "Sent" dipende dal server: verificarlo con un comando
IMAP `LIST` (vedi la sezione Configurazione più sopra per un esempio) prima di
valorizzare `imap.sent_mailbox` — su Bluehost/Dovecot è tipicamente
`INBOX.Sent`.

## Consultazione dei log

Dalla sezione **Log analisi** è possibile vedere, per ogni email elaborata:
data/ora, mittente, oggetto, punteggio di rischio, verdetto, eventuali avvisi
di lookalike ed eventuali rilevamenti VirusTotal, con filtri per intervallo di
date, verdetto e mittente. Lo stesso storico è disponibile anche come file
JSONL (`logs/analysis.jsonl` di default) per audit/esportazione esterna — vedi
`examples/log_example.jsonl` per il formato.

## Come funziona il rilevamento lookalike

Per ogni email, il dominio del mittente viene confrontato con ciascun dominio
protetto configurato usando due tecniche (in `spambox/worker/analyzers/lookalike.py`):

1. **Pattern esplicito "dominio.extra.tld"**: rileva il caso reale osservato
   (`miodominio.it.com` al posto di `miodominio.com`) verificando se il primo
   componente di un dominio protetto compare come label separata nel dominio
   del mittente, pur essendo domini diversi.
2. **Distanza di Levenshtein + rapporto di similarità**: se la distanza è
   entro la soglia configurata (`lookalike.levenshtein_max_distance`, default
   2) oppure il rapporto di similarità (`difflib.SequenceMatcher`) supera la
   soglia configurata (`lookalike.similarity_ratio_threshold`, default 0.82),
   il dominio viene segnalato come sospetto lookalike.

Un match di lookalike alza fortemente il punteggio di rischio (componente
dedicata, peso configurabile in `scoring.weight_lookalike`) e viene sempre
riportato in modo esplicito nella risposta inviata all'utente.

## Come funziona l'integrazione VirusTotal

Implementata in `spambox/worker/analyzers/virustotal.py`, usando direttamente
le API v3 REST (via `requests`), senza SDK di terze parti:

- **URL**: per ogni URL estratto dal corpo del messaggio (testo e HTML) si
  calcola l'id VirusTotal (`base64url(url)` senza padding) e si interroga
  `GET /api/v3/urls/{id}`. Se VT non ha ancora un report per quell'URL
  (HTTP 404) viene segnalato come "sconosciuto", **senza** effettuare
  l'upload/submit dell'URL (per non consumare quota inutilmente né introdurre
  attese di scansione).
- **Allegati**: per ogni allegato si calcola lo SHA-256 e si interroga
  `GET /api/v3/files/{sha256}`. Anche qui **nessun upload del file**: solo
  lookup dell'hash.
- Il numero di motori che rilevano una minaccia (`malicious`/`suspicious`) e
  le categorie restituite da VT vengono usati per alzare il punteggio di
  rischio finale e per generare un avviso esplicito nella risposta
  ("Uno o più link risultano segnalati come malevoli su VirusTotal").

## Come funziona il controllo età del dominio (RDAP)

Implementato in `spambox/worker/analyzers/domain_age.py`: interroga
[rdap.org](https://rdap.org) (bootstrap pubblico verso il registro RDAP
autoritativo per qualsiasi TLD, nessuna API key richiesta) per la data di
registrazione di un dominio. Se il dominio risulta registrato da meno di
`domain_age.suspicious_if_younger_than_days` giorni (default 30), viene
generato un avviso esplicito: le campagne di phishing usano spesso domini
appena creati per aggirare le blocklist basate sulla reputazione storica.
Come per gli altri analizzatori, un errore di rete o un dominio non trovato
su RDAP non blocca il resto dell'analisi.

**Importante — quale dominio viene controllato**: dato che un'email
sospetta arriva quasi sempre come *forward* da un collega di un dominio
autorizzato (non direttamente dal mittente esterno), controllare il From
del messaggio così come ricevuto da SpamBox controllerebbe sempre e solo un
dominio interno fidato, inutile ai fini dell'analisi. Il worker
(`spambox/worker/mime_parser.py`, funzione `_extract_quoted_sender_domains`)
risale invece al/ai mittente/i realmente sospetto/i annidato/i nel corpo del
forward (righe tipo "Da:"/"From:" nel testo citato, e link `mailto:`
nell'HTML — copre sia i forward "in-line" di Apple Mail sia le catene di
inoltro di Outlook), escludendo i domini già presenti tra i domini
autorizzati. Sia il controllo età dominio sia il rilevamento lookalike
vengono eseguiti su questi mittenti esterni individuati, non sul From
diretto del messaggio.

## Come funziona l'integrazione URLhaus

Implementata in `spambox/worker/analyzers/urlhaus.py`, complementare a
VirusTotal: interroga [URLhaus](https://urlhaus.abuse.ch) (progetto di
abuse.ch) per ogni URL estratto dal messaggio, con limiti di quota molto più
permissivi di VirusTotal. **Dal 2023 richiede una Auth-Key gratuita** anche
per le sole interrogazioni in lettura (prima non serviva): registrarsi su
[auth.abuse.ch](https://auth.abuse.ch/) e valorizzare `urlhaus.auth_key` in
`config.yaml` (o la variabile `SPAMBOX_URLHAUS_AUTH_KEY`). Senza chiave
configurata l'analisi URLhaus viene semplicemente saltata (nessun errore
bloccante), in modo analogo a come VirusTotal viene saltato senza API key.

## Come funziona l'integrazione Google Safe Browsing

Implementata in `spambox/worker/analyzers/safebrowsing.py`: lo stesso
servizio che alimenta gli avvisi "sito pericoloso" di Chrome/Firefox/Safari,
specificamente per phishing e malware. A differenza di VirusTotal/URLhaus,
questa API permette di controllare **tutti gli URL di un messaggio in
un'unica richiesta**. Richiede una API key gratuita di Google Cloud
(abilitare "Safe Browsing API" nella console, quota gratuita di 10.000
richieste/giorno) da valorizzare in `safebrowsing.api_key` (o
`SPAMBOX_SAFEBROWSING_API_KEY`). Senza chiave configurata l'analisi viene
saltata senza bloccare il resto.

## Rilevamento impersonificazione brand e Reply-To dirottato

Due euristiche complementari, implementate in
`spambox/worker/analyzers/brand_impersonation.py` e in
`spambox/worker/verdict.py` (`_reply_to_mismatch_component`), pensate per il
caso più comune di phishing reale: un'email che si spaccia per un corriere,
una banca o un'utility, inoltrata da un dipendente.

- **Impersonificazione di brand**: il worker risale al nome visualizzato e al
  dominio del mittente *originale* annidato nel testo del forward (non
  all'header del messaggio come ricevuto, che nei forward è sempre
  l'indirizzo di chi ha inoltrato). Se il nome dichiara un brand noto (es.
  "DHL", "ENEL", elenco in `KNOWN_BRANDS`) ma il dominio reale non è tra
  quelli legittimi di quel brand, scatta un avviso esplicito.
- **Reply-To dirottato**: se il From dichiarato e il Reply-To (anch'esso
  estratto dal testo citato del forward, non solo dagli header MIME) puntano
  a domini diversi e scorrelati, è un segnale di phishing indipendente dal
  riconoscere un brand — tecnica comune per dirottare le risposte (o una
  falsa "verifica di identità") verso l'attaccante mantenendo un mittente
  visibile credibile.

**Nota sui falsi positivi**: queste sono euristiche probabilistiche, non
prove certe (es. un'azienda può legittimamente usare un provider PEC terzo
come Reply-To). Per questo, da sole portano il verdetto solo a "Sospetta",
mai a "Altamente pericolosa" — serve che si accumuli almeno un secondo
segnale indipendente per salire di livello (vedi `compute_verdict` in
`verdict.py` per la logica completa dei due livelli di floor).

## Note sui rate-limit di VirusTotal

Il tier gratuito di VirusTotal impone tipicamente **4 richieste al minuto**
(oltre a limiti giornalieri/mensili). Il client (`_RateLimiter` in
`virustotal.py`) applica uno spacing minimo fra le richieste calcolato da
`virustotal.requests_per_minute` in configurazione: abbassare questo valore
se si usa una chiave con limiti più stringenti, alzarlo se si dispone di una
licenza a pagamento con quota maggiore.

In caso di superamento quota (HTTP 429) o di errore di rete/timeout, la
singola verifica VT viene marcata come `quota_exceeded` / `error` e **l'intera
analisi prosegue comunque** con gli altri segnali disponibili (Rspamd,
lookalike, SPF/DKIM/DMARC): un problema con VirusTotal non blocca mai
l'invio della risposta all'utente. Per contenere il numero di chiamate per
messaggio si possono limitare `virustotal.max_urls_per_message` e
`virustotal.max_attachments_per_message`.

## Diagnostica

`scripts/diagnose.py` verifica che ogni analizzatore chiami davvero la sua
API esterna e riconosca correttamente input **noti e deterministici**
(la stringa di test GTUBE per rspamd, il file di test EICAR per VirusTotal,
gli URL di test ufficiali di Google Safe Browsing), invece di limitarsi a
controllare "nessun errore":

```bash
cd /opt/spambox
sudo -u spambox bash -c '
set -a
source config/spambox.env
set +a
./venv/bin/python scripts/diagnose.py
'
```

Utile dopo ogni deploy, dopo aver rinnovato una API key, o periodicamente per
accorgersi se un servizio ha smesso di funzionare in silenzio.

## Deployment su Raspberry Pi / DietPi

Il sistema gira bene anche su hardware modesto come un Raspberry Pi 3 B+ con
DietPi: il worker è un processo **oneshot** lanciato dal timer systemd (non
resta in memoria tra un ciclo e l'altro) e la webapp è un'app di sola
amministrazione, usata saltuariamente. Rspamd (scritto in C) è leggero e
disponibile via `apt`/`dietpi-software` anche su ARM.

Accorgimenti specifici:

- `requirements.txt` usa `uvicorn` senza l'extra `[standard]` proprio per
  evitare la compilazione di `uvloop`/`httptools` (estensioni C spesso prive
  di wheel precompilate per ARM): l'ASGI server standard basato su `asyncio`
  è più che sufficiente per un'interfaccia interna.
- Per limitare l'usura della SD card (SQLite in WAL scrive spesso su disco):
  usare una SD di qualità o, meglio, avviare da SSD/chiavetta USB se
  possibile, e installare la rotazione log fornita:

  ```bash
  sudo cp systemd/spambox-logrotate.conf /etc/logrotate.d/spambox
  ```

- Su DietPi i pacchetti systemd sono nativi: le unit in `systemd/` si
  installano senza modifiche (vedi sezione precedente).

## Backup

Non si fa il backup dell'intero sistema (SD/immagine): l'installazione è
interamente riproducibile dal repository + configurazione, quindi l'unico
stato reale da salvare è il **database SQLite** (log delle analisi e domini
protetti) e i **file di configurazione**. `scripts/backup.sh`:

1. esegue un dump sicuro del DB con `sqlite3 ... ".backup"` (a differenza di
   una copia a freddo del file, funziona correttamente anche con WAL attivo
   mentre il worker potrebbe scrivere);
2. copia `config/config.yaml` e `config/spambox.env`;
3. comprime tutto in un archivio temporaneo sotto `/tmp` (rimosso a fine
   esecuzione, anche in caso di errore);
4. lo invia con [`rclone`](https://rclone.org/) verso lo storage cloud
   configurato;
5. applica una retention sui backup remoti più vecchi di N giorni.

Setup:

```bash
# rclone deve essere già installato e configurato con il proprio provider cloud
rclone config

cp config/backup.env.example config/backup.env
# valorizzare RCLONE_REMOTE (e RCLONE_CONFIG se non nel default $HOME/.config/rclone/rclone.conf)

./scripts/backup.sh   # test manuale
```

Per l'esecuzione automatica giornaliera:

```bash
sudo cp systemd/spambox-backup.service systemd/spambox-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now spambox-backup.timer
```

**Nota sicurezza**: `config/spambox.env` contiene credenziali reali (password
IMAP/SMTP, API key VirusTotal). L'archivio di backup viene creato con
permessi `600` e cancellato subito dopo l'invio, ma il contenuto arriva in
chiaro sullo storage cloud di destinazione: usare un remote rclone con
crittografia (`rclone config` -> tipo `crypt`) se il provider cloud non è
considerato pienamente fidato, o quantomeno assicurarsi che il bucket/cartella
di destinazione sia privato.

## Sicurezza

- Nessuna credenziale è hardcoded: tutto passa da `config.yaml` e/o variabili
  d'ambiente (`SPAMBOX_*`), con le seconde che hanno sempre precedenza.
- Il worker e la webapp vanno eseguiti con un utente di sistema dedicato e
  privilegi minimi (vedi unit systemd in `systemd/`, che includono
  `ProtectSystem=strict`, `NoNewPrivileges=true`, ecc.).
- L'interfaccia web richiede autenticazione HTTP Basic; la password è
  confrontata come hash SHA-256 (mai in chiaro) usando `hmac.compare_digest`
  per evitare timing attack.
- Nessuna password o segreto viene mai scritto nei log applicativi o nel
  JSONL di analisi.
- Si raccomanda di esporre l'interfaccia web solo in rete interna o dietro un
  reverse proxy con HTTPS.

## Estendere il sistema

Vedi [`docs/EXTENDING.md`](docs/EXTENDING.md) per come aggiungere in modo
pulito: scansione allegati con ClamAV, altri feed di reputazione (OpenPhish,
PhishTank, AbuseIPDB), e come si inserirebbe in futuro un'integrazione con
MISP.

## Contribuire

Le contribuzioni sono benvenute — vedi [`CONTRIBUTING.md`](CONTRIBUTING.md)
per le linee guida. Il modo più semplice per iniziare: aggiungere un brand
mancante alla lista anti-impersonificazione in
`spambox/worker/analyzers/brand_impersonation.py`, o segnalare (con
[`CONTRIBUTING.md`](CONTRIBUTING.md#segnalare-un-bug-o-una-truffa-non-rilevata))
un'email reale non rilevata correttamente.

## Licenza

Distribuito con licenza [MIT](LICENSE).
