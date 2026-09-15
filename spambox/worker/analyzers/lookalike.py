"""Rilevazione domini lookalike / typosquatting rispetto ai domini protetti.

Combina distanza di Levenshtein (implementazione pura Python, nessuna
dipendenza compilata richiesta) con un controllo di similarita' e un
controllo esplicito per il pattern "dominio.tld1.tld2" osservato in campagne
reali (es. miodominio.it.com al posto di miodominio.com).
"""
from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

from spambox.config import LookalikeConfig


def levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current_row = [i]
        for j, cb in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            replace_cost = previous_row[j - 1] + (ca != cb)
            current_row.append(min(insert_cost, delete_cost, replace_cost))
        previous_row = current_row
    return previous_row[-1]


def _normalize(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


@dataclass
class LookalikeMatch:
    suspect_domain: str
    legitimate_domain: str
    distance: int
    similarity_ratio: float
    reason: str


def _contains_domain_as_prefix(suspect: str, legit: str) -> bool:
    """Rileva il pattern 'legit.extra.tld' (es. miodominio.it.com vs miodominio.com)."""
    legit_root = legit.split(".")[0]
    suspect_labels = suspect.split(".")
    return legit_root in suspect_labels and suspect != legit and legit_root != ""


def find_lookalike_matches(
    sender_domain: str, protected_domains: list[str], config: LookalikeConfig
) -> list[LookalikeMatch]:
    sender_domain = _normalize(sender_domain)
    matches: list[LookalikeMatch] = []
    if not sender_domain:
        return matches

    for legit in protected_domains:
        legit_norm = _normalize(legit)
        if not legit_norm or legit_norm == sender_domain:
            continue

        distance = levenshtein_distance(sender_domain, legit_norm)
        ratio = SequenceMatcher(None, sender_domain, legit_norm).ratio()

        if _contains_domain_as_prefix(sender_domain, legit_norm):
            matches.append(
                LookalikeMatch(
                    suspect_domain=sender_domain,
                    legitimate_domain=legit_norm,
                    distance=distance,
                    similarity_ratio=ratio,
                    reason=(
                        f"Il mittente usa un indirizzo con dominio '{sender_domain}', molto simile "
                        f"a quello ufficiale '{legit_norm}' ma con un'estensione diversa: è una "
                        "tecnica comune usata nelle truffe via email per sembrare affidabili"
                    ),
                )
            )
            continue

        if distance <= config.levenshtein_max_distance or ratio >= config.similarity_ratio_threshold:
            matches.append(
                LookalikeMatch(
                    suspect_domain=sender_domain,
                    legitimate_domain=legit_norm,
                    distance=distance,
                    similarity_ratio=round(ratio, 3),
                    reason=(
                        f"Il dominio del mittente '{sender_domain}' è molto simile a quello "
                        f"ufficiale '{legit_norm}': potrebbe essere un tentativo di imitazione"
                    ),
                )
            )

    return matches
