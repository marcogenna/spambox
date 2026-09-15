"""Integrazione con Google Safe Browsing API v4 (Lookup API).

Lo stesso servizio che alimenta gli avvisi "sito pericoloso" di Chrome,
Firefox e Safari, specificamente per phishing e malware — complementare a
VirusTotal e URLhaus. Richiede una API key gratuita di Google Cloud
(abilitare "Safe Browsing API" nella console, quota gratuita di 10.000
richieste/giorno). A differenza degli altri due analizzatori, questa API
permette di controllare più URL in un'unica richiesta.
"""
from __future__ import annotations

import logging
from typing import Any

import requests

from spambox.config import SafeBrowsingConfig

logger = logging.getLogger("spambox.safebrowsing")

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def analyze_urls(urls: list[str], config: SafeBrowsingConfig) -> dict[str, Any]:
    if not config.enabled:
        return {"available": False, "reason": "disabilitato in configurazione", "matches": []}
    if not config.api_key or config.api_key.startswith("PLACEHOLDER"):
        logger.warning("API key Google Safe Browsing non configurata: analisi saltata")
        return {"available": False, "reason": "API key non configurata", "matches": []}

    checked_urls = urls[: config.max_urls_per_message]
    if not checked_urls:
        return {"available": True, "quota_exceeded": False, "matches": []}

    body = {
        "client": {"clientId": "spambox", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in checked_urls],
        },
    }

    try:
        resp = requests.post(
            f"{config.base_url.rstrip('/')}/threatMatches:find",
            params={"key": config.api_key},
            json=body,
            timeout=config.request_timeout_seconds,
        )
        if resp.status_code == 429:
            logger.warning("Quota Google Safe Browsing superata")
            return {"available": True, "quota_exceeded": True, "matches": []}
        if resp.status_code in (400, 403):
            logger.warning("Google Safe Browsing: richiesta rifiutata (%s) - API key valida?", resp.status_code)
            return {"available": False, "reason": f"richiesta rifiutata (status {resp.status_code})", "matches": []}
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as exc:
        logger.warning("Google Safe Browsing non raggiungibile: %s", exc)
        return {"available": False, "reason": str(exc), "matches": []}
    except ValueError as exc:
        logger.warning("Risposta Google Safe Browsing non valida: %s", exc)
        return {"available": False, "reason": "risposta non valida", "matches": []}

    matches = [
        {
            "url": m.get("threat", {}).get("url"),
            "threat_type": m.get("threatType"),
            "platform_type": m.get("platformType"),
        }
        for m in data.get("matches", [])
    ]
    return {"available": True, "quota_exceeded": False, "matches": matches}
