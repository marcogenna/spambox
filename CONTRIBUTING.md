# Contribuire a SpamBox

Grazie per l'interesse! Alcune linee guida rapide.

## Come proporre una modifica

1. Fai un fork del repository e crea un branch dedicato (`git checkout -b fix/nome-modifica`).
2. Scrivi codice coerente con lo stile esistente: niente commenti che spiegano
   l'ovvio, error handling solo dove serve davvero, nessuna astrazione
   prematura per casi ipotetici.
3. Se aggiungi un analizzatore (nuova fonte di threat intel, nuova euristica),
   segui il pattern descritto in [`docs/EXTENDING.md`](docs/EXTENDING.md):
   non deve mai sollevare eccezioni verso il chiamante, deve essere
   disattivabile da configurazione, deve restituire dati serializzabili in JSON.
4. Testa le modifiche prima di aprire la PR — non esiste ancora una suite di
   test automatici, quindi verifica manualmente con `scripts/diagnose.py` e,
   se possibile, con un'email di prova reale attraverso il worker.
5. Apri una Pull Request descrivendo cosa cambia e perché.

## Segnalare un bug o una truffa non rilevata

Se SpamBox non rileva (o segnala erroneamente) un'email reale, apri una
Issue includendo:
- il verdetto/punteggio ottenuto e i motivi mostrati;
- il sorgente `.eml` grezzo del messaggio, **con dati personali/aziendali
  sensibili oscurati** (indirizzi email reali, nomi, numeri di conto, ecc.) —
  non incollare mai un'email reale non anonimizzata in una Issue pubblica.

## Aggiungere brand alla lista anti-impersonificazione

`spambox/worker/analyzers/brand_impersonation.py` contiene un dizionario
`KNOWN_BRANDS` (brand → domini legittimi). È il modo più semplice e utile di
contribuire: se un brand comunemente impersonato nel tuo paese/settore manca
dalla lista, aggiungilo con una PR minimale.

## Sicurezza

Se scopri una vulnerabilità (non un semplice bug di rilevamento falsi
positivi/negativi), non aprire una Issue pubblica: contatta i maintainer
privatamente.
