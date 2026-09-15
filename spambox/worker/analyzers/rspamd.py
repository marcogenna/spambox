"""Integrazione con Rspamd via API HTTP (controller worker, endpoint checkv2)."""
from __future__ import annotations

import logging
from typing import Any

import requests

from spambox.config import RspamdConfig

logger = logging.getLogger("spambox.rspamd")


def check_message(raw_bytes: bytes, config: RspamdConfig) -> dict[str, Any]:
    """Invia il messaggio raw a Rspamd e restituisce score/azione/simboli.

    In caso di errore (rspamd non raggiungibile, timeout, ecc.) l'analisi non
    fallisce: viene restituito un risultato "unavailable" con score neutro,
    così il resto della pipeline può proseguire.
    """
    if not config.enabled:
        return {"available": False, "reason": "disabilitato in configurazione"}

    headers = {}
    if config.password:
        headers["Password"] = config.password

    try:
        resp = requests.post(
            f"{config.base_url.rstrip('/')}/checkv2",
            data=raw_bytes,
            headers=headers,
            timeout=config.timeout_seconds,
        )
        resp.raise_for_status()
        data = resp.json()
        symbols = data.get("symbols", {})
        return {
            "available": True,
            "score": data.get("score", 0.0),
            "required_score": data.get("required_score"),
            "action": data.get("action"),
            "symbols": sorted(symbols.keys()),
            "symbols_detail": {
                name: {
                    "score": sym.get("score"),
                    "description": sym.get("description", ""),
                }
                for name, sym in symbols.items()
            },
        }
    except requests.exceptions.RequestException as exc:
        logger.warning("Rspamd non raggiungibile: %s", exc)
        return {"available": False, "reason": str(exc), "score": 0.0}
    except (ValueError, KeyError) as exc:
        logger.warning("Risposta Rspamd non valida: %s", exc)
        return {"available": False, "reason": "risposta non valida", "score": 0.0}
