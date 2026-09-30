"""Rilevazione di richieste di credenziali/dati sensibili nel testo del
messaggio: molte email di phishing non impersonano un brand riconoscibile
(quindi non intercettate da brand_impersonation.py) né usano un dominio
sospetto (quindi non intercettate da lookalike.py), ma si affidano al
linguaggio classico dell'ingegneria sociale — "il tuo account è sospeso,
accedi subito", "conferma i tuoi dati di pagamento", "verifica la tua
identità" — abbinato a un link su cui cliccare.

Euristica, non prova diretta: anche servizi legittimi a volte chiedono di
"accedere al tuo account" o "aggiornare i dati di pagamento" (scadenza
carta, rinnovo abbonamento). Per questo richiede la combinazione di (a)
una frase sospetta E (b) almeno un link nel messaggio, e resta nel livello
euristico del punteggio, non in quello confermato.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Frasi tipiche delle richieste di credenziali/dati sensibili sotto pressione,
# in italiano e inglese. Raggruppate per intento in modo che la reason possa
# spiegare CHE tipo di richiesta è stata rilevata.
_PATTERNS: dict[str, re.Pattern] = {
    "sospensione dell'account (pressione a agire subito)": re.compile(
        r"""account\s+(?:è\s+stato\s+)?(?:sospeso|bloccato|disattivato|limitato)|
            account\s+(?:has\s+been\s+)?(?:suspended|locked|disabled|restricted)|
            sospension[ei]\s+dell[' ]?account|
            attivit[àa]\s+sospett[ae]\s+(?:rilevat[ae]|sul\s+tuo\s+account)|
            unusual\s+activity\s+(?:detected|on\s+your\s+account)""",
        re.IGNORECASE | re.VERBOSE,
    ),
    "richiesta di verificare/confermare l'identità o l'account": re.compile(
        r"""verifica(?:re)?\s+(?:subito\s+)?(?:la\s+tua\s+identit[àa]|il\s+tuo\s+account)|
            conferma(?:re)?\s+(?:i\s+tuoi\s+dati|la\s+tua\s+identit[àa]|il\s+tuo\s+account)|
            verify\s+your\s+(?:identity|account)|
            confirm\s+your\s+(?:identity|account|details)""",
        re.IGNORECASE | re.VERBOSE,
    ),
    "richiesta di aggiornare dati di pagamento/bancari": re.compile(
        r"""aggiorna(?:re)?\s+(?:i\s+tuoi\s+)?dati\s+(?:di\s+pagamento|bancari)|
            fornisc[ai]\s+(?:i\s+tuoi\s+)?dati\s+(?:bancari|della\s+carta)|
            update\s+your\s+payment\s+(?:details|information|method)|
            your\s+payment\s+(?:failed|could\s+not\s+be\s+processed)""",
        re.IGNORECASE | re.VERBOSE,
    ),
    "richiesta esplicita di inserire credenziali": re.compile(
        r"""inserisc[ai]\s+(?:la\s+tua\s+)?password|
            accedi\s+(?:subito\s+)?(?:al\s+tuo\s+account|con\s+le\s+tue\s+credenziali)|
            log\s*in\s+to\s+your\s+account|
            enter\s+your\s+(?:password|credentials)""",
        re.IGNORECASE | re.VERBOSE,
    ),
}


@dataclass
class PhishingLanguageMatch:
    category: str
    reason: str


def find_phishing_language(
    text_body: str, html_body: str, urls: list[str]
) -> list[PhishingLanguageMatch]:
    if not urls:
        # Senza un link su cui l'utente sarebbe spinto a cliccare, la sola
        # frase non basta: troppi falsi positivi (es. notifiche generiche
        # senza call-to-action).
        return []

    combined_text = f"{text_body}\n{html_body}"
    matches: list[PhishingLanguageMatch] = []
    for category, pattern in _PATTERNS.items():
        if pattern.search(combined_text):
            matches.append(
                PhishingLanguageMatch(
                    category=category,
                    reason=(
                        f"Il messaggio contiene un linguaggio tipico delle truffe di phishing "
                        f"({category}), abbinato a un link su cui cliccare"
                    ),
                )
            )
    return matches
