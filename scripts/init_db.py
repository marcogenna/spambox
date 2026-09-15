#!/usr/bin/env python3
"""Inizializza il database SQLite (schema) leggendo il path dalla configurazione."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from spambox.config import load_config
from spambox import db

if __name__ == "__main__":
    config = load_config()
    db.init_db(config.storage.sqlite_path)
    print(f"Database inizializzato in {config.storage.sqlite_path}")
