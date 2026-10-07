"""Coerenza tra nome visualizzato e indirizzo del mittente.

Nei messaggi di phishing generati in serie l'indirizzo è spesso del tipo
nome.cognome@dominio (aspetto "personale" e credibile) mentre il nome
visualizzato appartiene a un'altra persona: es. "INDRI RICCARDO"
<lazar.plackovic@dominio-non-pertinente.it>. In una comunicazione vera nome
visualizzato e parte locale dell'indirizzo condividono quasi sempre almeno
una parola.

Euristica prudente, solo per indirizzi nel formato nome.cognome e nomi
visualizzati di 2+ parole: alias, cognomi cambiati o soprannomi esistono, per
questo resta nel livello euristico del punteggio.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


@dataclass
class SenderIdentityMatch:
    display_name: str
    address: str
    reason: str


def _tokens(text: str) -> set[str]:
    folded = unicodedata.normalize("NFKD", text.lower())
    folded = "".join(c for c in folded if not unicodedata.combining(c))
    return {t for t in re.findall(r"[a-z]+", folded) if len(t) >= 2}


def find_sender_identity_mismatch(
    quoted_addresses: list[tuple[str, str]],
) -> list[SenderIdentityMatch]:
    matches: list[SenderIdentityMatch] = []
    for display_name, address in quoted_addresses:
        local = address.split("@", 1)[0]
        local_parts = re.split(r"[._-]", local)
        if len(local_parts) != 2 or not all(p.isalpha() and len(p) >= 2 for p in local_parts):
            continue
        display_tokens = _tokens(display_name)
        if len(display_tokens) < 2:
            continue
        if display_tokens & _tokens(" ".join(local_parts)):
            continue
        matches.append(
            SenderIdentityMatch(
                display_name=display_name,
                address=address,
                reason=(
                    f"Il nome del mittente ('{display_name.strip()}') non corrisponde "
                    f"all'indirizzo da cui scrive ('{address}'): tecnica tipica dei messaggi "
                    "generati in serie che usano nomi di persona credibili"
                ),
            )
        )
    return matches
