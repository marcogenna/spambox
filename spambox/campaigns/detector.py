"""Riconosce, dentro un'email inoltrata a SpamBox, il link di tracciamento
di una campagna di phishing simulato: se il dipendente ha inoltrato invece
di cliccare, ha superato il test.
"""
from __future__ import annotations

import re

from spambox import db

_CLICK_TOKEN_RE = re.compile(r"/sim/click/([\w-]+)")


def find_campaign_token_in_urls(urls: list[str]) -> str | None:
    for url in urls:
        match = _CLICK_TOKEN_RE.search(url)
        if match:
            return match.group(1)
    return None


def check_and_mark_reported(sqlite_path: str, urls: list[str]):
    """Se uno degli URL del messaggio corrisponde al link di una campagna
    attiva, marca il target come "segnalato correttamente" e restituisce la
    riga del target (per costruire la risposta di rinforzo); altrimenti None.
    """
    token = find_campaign_token_in_urls(urls)
    if not token:
        return None

    target = db.find_target_by_token(sqlite_path, token)
    if target is None:
        return None

    db.mark_target_reported(sqlite_path, token)
    return target
