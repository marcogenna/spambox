"""Controllo età del dominio mittente via RDAP (successore di WHOIS).

Un dominio registrato da pochissimi giorni è un segnale forte di phishing:
le campagne di attacco spesso usano domini appena creati per aggirare le
blocklist basate sulla reputazione storica. Usa rdap.org come bootstrap
verso il registro RDAP autoritativo per qualsiasi TLD, senza bisogno di API
key. In caso di errore/timeout/dominio non trovato l'analisi non fallisce:
restituisce un risultato "unavailable" a impatto nullo sullo scoring.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import requests

from spambox.config import DomainAgeConfig

logger = logging.getLogger("spambox.domain_age")


def _parse_registration_date(rdap_data: dict[str, Any]) -> datetime | None:
    for event in rdap_data.get("events", []):
        if event.get("eventAction") == "registration":
            date_str = event.get("eventDate")
            if not date_str:
                continue
            try:
                return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except ValueError:
                continue
    return None


def check_domain_age(domain: str, config: DomainAgeConfig) -> dict[str, Any]:
    if not config.enabled:
        return {"available": False, "reason": "disabilitato in configurazione"}
    if not domain:
        return {"available": False, "reason": "dominio non determinabile"}

    try:
        resp = requests.get(
            f"{config.base_url.rstrip('/')}/domain/{domain}",
            timeout=config.request_timeout_seconds,
            headers={"Accept": "application/rdap+json"},
        )
        if resp.status_code == 404:
            return {"available": False, "reason": "dominio non trovato su RDAP"}
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as exc:
        logger.warning("RDAP non raggiungibile per %s: %s", domain, exc)
        return {"available": False, "reason": str(exc)}
    except ValueError as exc:
        logger.warning("Risposta RDAP non valida per %s: %s", domain, exc)
        return {"available": False, "reason": "risposta non valida"}

    registration_date = _parse_registration_date(data)
    if registration_date is None:
        return {"available": False, "reason": "data di registrazione non presente nella risposta RDAP"}

    age_days = (datetime.now(timezone.utc) - registration_date).days
    return {
        "available": True,
        "domain": domain,
        "registration_date": registration_date.date().isoformat(),
        "age_days": age_days,
        "is_recent": age_days < config.suspicious_if_younger_than_days,
    }
