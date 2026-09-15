"""Integrazione con URLhaus (abuse.ch): lista di URL malevoli in tempo reale.

Complementare a VirusTotal, con limiti di quota molto più permessivi. Dal
2023 abuse.ch richiede una "Auth-Key" gratuita anche per le interrogazioni
di sola lettura (in precedenza non serviva): registrarsi su
https://auth.abuse.ch/ e valorizzare urlhaus.auth_key in config.yaml (o
SPAMBOX_URLHAUS_AUTH_KEY). Senza key le richieste falliscono con 401: come
per VirusTotal, l'errore viene gestito senza mai far fallire l'intera analisi.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import requests

from spambox.config import UrlhausConfig

logger = logging.getLogger("spambox.urlhaus")


class _RateLimiter:
    def __init__(self, requests_per_minute: int):
        self.min_interval = 60.0 / max(requests_per_minute, 1)
        self._last_call = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_call = time.monotonic()


def _lookup_url(url: str, config: UrlhausConfig, limiter: _RateLimiter) -> dict[str, Any]:
    limiter.wait()
    headers = {}
    if config.auth_key:
        headers["Auth-Key"] = config.auth_key
    try:
        resp = requests.post(
            f"{config.base_url.rstrip('/')}/url/",
            data={"url": url},
            headers=headers,
            timeout=config.request_timeout_seconds,
        )
        if resp.status_code == 429:
            return {"url": url, "status": "quota_exceeded"}
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as exc:
        logger.warning("URLhaus non raggiungibile per %s: %s", url, exc)
        return {"url": url, "status": "error", "detail": str(exc)}
    except ValueError as exc:
        logger.warning("Risposta URLhaus non valida per %s: %s", url, exc)
        return {"url": url, "status": "error", "detail": "risposta non valida"}

    if data.get("query_status") != "ok":
        return {"url": url, "status": "unknown"}

    return {
        "url": url,
        "status": "malicious",
        "threat": data.get("threat"),
        "url_status": data.get("url_status"),
        "tags": data.get("tags") or [],
    }


def analyze_urls(urls: list[str], config: UrlhausConfig) -> dict[str, Any]:
    if not config.enabled:
        return {"available": False, "reason": "disabilitato in configurazione", "urls": []}
    if not config.auth_key or config.auth_key.startswith("PLACEHOLDER"):
        logger.warning("Auth-Key URLhaus non configurata: analisi URLhaus saltata")
        return {"available": False, "reason": "Auth-Key non configurata", "urls": []}

    limiter = _RateLimiter(config.requests_per_minute)
    results = [_lookup_url(u, config, limiter) for u in urls[: config.max_urls_per_message]]
    return {
        "available": True,
        "quota_exceeded": any(r.get("status") == "quota_exceeded" for r in results),
        "urls": results,
    }
