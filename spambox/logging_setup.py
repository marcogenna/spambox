"""Logging applicativo (testuale, per systemd journal) e log di analisi (JSONL)."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def setup_app_logging(log_path: str, level: int = logging.INFO) -> logging.Logger:
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("spambox")
    logger.setLevel(level)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    return logger


def append_analysis_jsonl(jsonl_path: str, entry: dict[str, Any]) -> None:
    """Scrive una riga JSON con il risultato dell'analisi.

    Non include mai credenziali o dati sensibili: solo metadati del messaggio
    e risultati delle analisi (rspamd, VirusTotal, lookalike).
    """
    Path(jsonl_path).parent.mkdir(parents=True, exist_ok=True)
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), **entry}
    with open(jsonl_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
