#!/usr/bin/env python3
"""Diagnostica: verifica che ogni analizzatore di SpamBox chiami davvero la
sua API esterna e riconosca correttamente input noti.

Usa campioni di test ufficiali/riconosciuti (EICAR per gli antivirus, GTUBE
per i filtri antispam, gli URL di test pubblici di Google Safe Browsing) in
modo da avere un risultato atteso deterministico, invece di dover aspettare
una vera email sospetta per scoprire se un servizio è configurato bene.

Uso:
    cd /opt/spambox
    sudo -u spambox bash -c '
    set -a; source config/spambox.env; set +a
    ./venv/bin/python scripts/diagnose.py
    '
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from spambox.config import load_config
from spambox.worker.analyzers import domain_age, rspamd, safebrowsing, urlhaus, virustotal

# Stringa di test standard SpamAssassin/rspamd: qualunque filtro antispam
# configurato correttamente DEVE segnalarla come spam (regola GTUBE).
GTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
TEST_MESSAGE = (
    f"From: test@example.com\r\nTo: test@example.com\r\nSubject: test\r\n\r\n{GTUBE}\r\n"
).encode()

# File di test EICAR: riconosciuto da (quasi) tutti i motori antivirus come
# file di test standard, non e' malware reale, presente da anni su VirusTotal.
# Lo si calcola dalla stringa di test ufficiale invece di scrivere l'hash a
# mano, per evitare errori di trascrizione.
EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = hashlib.sha256(EICAR_STRING.encode()).hexdigest()

# URL di test ufficiali pubblicati da Google per verificare integrazioni con
# Safe Browsing: restituiscono SEMPRE un match, non sono siti reali.
SAFEBROWSING_TEST_URLS = [
    "http://testsafebrowsing.appspot.com/s/malware.html",
    "http://testsafebrowsing.appspot.com/s/phishing.html",
]


def _status(ok: bool, warn: bool = False) -> str:
    if warn:
        return "⚠️  ATTENZIONE"
    return "✅ OK" if ok else "❌ PROBLEMA"


def main() -> int:
    config = load_config()
    problems = 0

    print("=== Rspamd ===")
    result = rspamd.check_message(TEST_MESSAGE, config.rspamd)
    if not result.get("available"):
        print(_status(False), "- non raggiungibile:", result.get("reason"))
        problems += 1
    elif "GTUBE" in result.get("symbols", []):
        print(_status(True), f"- raggiungibile, GTUBE riconosciuta (score={result.get('score')})")
    else:
        print(_status(False, warn=True), f"- raggiungibile ma GTUBE non rilevata (score={result.get('score')}, simboli={result.get('symbols')})")
        problems += 1

    print("\n=== VirusTotal ===")
    result = virustotal.analyze_urls_and_attachments([], [EICAR_SHA256], config.virustotal)
    if not result.get("available"):
        print(_status(False), "- disattivo/non configurato:", result.get("reason"))
        problems += 1
    else:
        files = result.get("files", [])
        item = files[0] if files else {}
        status = item.get("status", "n/d")
        if status == "malicious":
            print(_status(True), f"- API key valida, file EICAR di test correttamente rilevato come malevolo")
        else:
            detail = item.get("detail", "")
            print(_status(False, warn=True), f"- API risponde ma EICAR non risulta malevolo (status={status}, dettaglio: {detail})")
            problems += 1

    print("\n=== URLhaus ===")
    result = urlhaus.analyze_urls(["http://example.com"], config.urlhaus)
    if not result.get("available"):
        print(_status(False), "- disattivo/non configurato:", result.get("reason"))
        problems += 1
    else:
        item_status = result.get("urls", [{}])[0].get("status")
        if item_status in ("unknown", "malicious"):
            print(_status(True), f"- Auth-Key valida, risposta ricevuta (status={item_status})")
        else:
            print(_status(False, warn=True), f"- risposta inattesa: {result.get('urls')}")
            problems += 1

    print("\n=== Google Safe Browsing ===")
    result = safebrowsing.analyze_urls(SAFEBROWSING_TEST_URLS, config.safebrowsing)
    if not result.get("available"):
        print(_status(False), "- disattivo/non configurato:", result.get("reason"))
        problems += 1
    elif result.get("matches"):
        print(_status(True), f"- API key valida, {len(result['matches'])} URL di test riconosciuti correttamente come minaccia")
    else:
        print(_status(False, warn=True), "- API risponde ma gli URL di test ufficiali non risultano segnalati - controllare la API key/l'abilitazione dell'API")
        problems += 1

    print("\n=== Controllo età dominio (RDAP) ===")
    result = domain_age.check_domain_age("google.com", config.domain_age)
    if result.get("available") and result.get("age_days", 0) > 365:
        print(_status(True), f"- funzionante (google.com: {result['age_days']} giorni)")
    else:
        print(_status(False), "- problema:", result.get("reason", result))
        problems += 1

    print("\n" + "=" * 40)
    if problems == 0:
        print("Tutti i controlli funzionano correttamente.")
    else:
        print(f"{problems} controllo/i con problemi - vedi sopra.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
