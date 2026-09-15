"""Entry point del worker SpamBox.

Esegue un singolo "giro" di polling: connessione IMAP, recupero messaggi non
elaborati, analisi (rspamd + VirusTotal + lookalike + auth), invio verdetto via
SMTP, logging su SQLite e su file JSONL. Pensato per essere lanciato da un
timer systemd ogni pochi minuti (vedi systemd/spambox-worker.timer), ma può
anche essere eseguito manualmente per test.
"""
from __future__ import annotations

import argparse
import logging
import sys

from spambox import db
from spambox.config import Config, load_config
from spambox.logging_setup import append_analysis_jsonl, setup_app_logging
from spambox.worker.analyzers import domain_age, rspamd, safebrowsing, urlhaus, virustotal
from spambox.worker.analyzers.brand_impersonation import find_brand_impersonation
from spambox.worker.analyzers.lookalike import find_lookalike_matches
from spambox.worker.imap_client import ImapError, ImapSession
from spambox.worker.mime_parser import parse_message
from spambox.worker.responder import send_verdict_email
from spambox.worker.verdict import compute_verdict

logger = logging.getLogger("spambox.worker")


def is_domain_allowed(domain: str, allowed_domains: list[str]) -> bool:
    """True se 'domain' coincide con uno degli allowed_domains, o e' un suo
    sottodominio (es. 'mail.miaazienda.com' e' autorizzato se 'miaazienda.com'
    e' in elenco)."""
    domain = domain.strip().lower().rstrip(".")
    for allowed in allowed_domains:
        allowed = allowed.strip().lower().rstrip(".")
        if not allowed:
            continue
        if domain == allowed or domain.endswith("." + allowed):
            return True
    return False


def build_unauthorized_log_entry(uid: str, parsed) -> dict:
    reason = (
        f"Email ignorata: il dominio del mittente ('{parsed.from_domain}') non è "
        "nell'elenco dei domini autorizzati a usare questo servizio"
    )
    logger.info("UID %s ignorato: mittente non autorizzato (%s)", uid, parsed.from_domain)
    return {
        "message_uid": uid,
        "from_address": parsed.from_address,
        "reply_to_address": parsed.reply_to_address,
        "subject": parsed.subject,
        "risk_score": 0.0,
        "verdict": "Ignorata",
        "reasons": [reason],
        "lookalike": {"matches": []},
        "virustotal": {"available": False},
        "urlhaus": {"available": False},
        "safebrowsing": {"available": False},
        "rspamd": {"available": False},
        "domain_age": {"available": False},
        "brand_impersonation": {"matches": []},
        "auth": parsed.auth_results,
        "response_sent": False,
        "error": None,
    }


def process_one_message(
    uid: str, raw_bytes: bytes, message, config: Config, allowed_forwarder_domains: list[str]
) -> dict:
    parsed = parse_message(raw_bytes, message)

    if not is_domain_allowed(parsed.from_domain, allowed_forwarder_domains):
        entry = build_unauthorized_log_entry(uid, parsed)
        db.insert_analysis_log(config.storage.sqlite_path, entry)
        append_analysis_jsonl(config.storage.analysis_jsonl_path, entry)
        return entry

    rspamd_result = rspamd.check_message(raw_bytes, config.rspamd)

    # Allegati "veri" (Content-Disposition: attachment) prima delle immagini
    # inline decorative della firma: altrimenti, con molte immagini di firma,
    # il limite max_attachments_per_message potrebbe escludere proprio
    # l'allegato pericoloso dal controllo VirusTotal (falso negativo).
    prioritized_attachments = sorted(parsed.attachments, key=lambda a: a.is_inline)
    attachment_hashes = [a.sha256 for a in prioritized_attachments]
    vt_result = virustotal.analyze_urls_and_attachments(
        parsed.urls, attachment_hashes, config.virustotal
    )
    urlhaus_result = urlhaus.analyze_urls(parsed.urls, config.urlhaus)
    safebrowsing_result = safebrowsing.analyze_urls(parsed.urls, config.safebrowsing)

    # parsed.from_domain è sempre un dominio autorizzato (interno) a questo
    # punto, altrimenti l'email sarebbe già stata ignorata sopra: controllarne
    # l'età o il lookalike non avrebbe senso (è per definizione un dominio
    # fidato). Il mittente esterno "vero" da controllare, in un forward
    # in-line, è annidato nel corpo del messaggio (parsed.quoted_sender_domains)
    # e non nell'header From del messaggio come ricevuto da SpamBox.
    external_candidate_domains = [
        d for d in parsed.quoted_sender_domains
        if not is_domain_allowed(d, allowed_forwarder_domains)
    ][:3]

    domain_age_result = {"available": False, "reason": "nessun mittente esterno individuato nel forward"}
    for candidate in external_candidate_domains:
        result = domain_age.check_domain_age(candidate, config.domain_age)
        if result.get("available") and (
            not domain_age_result.get("available") or result.get("is_recent")
        ):
            domain_age_result = result
            if result.get("is_recent"):
                break

    protected_domains = [row["domain"] for row in db.list_domains(config.storage.sqlite_path)]
    lookalike_matches = []
    for candidate in external_candidate_domains:
        lookalike_matches.extend(
            find_lookalike_matches(candidate, protected_domains, config.lookalike)
        )

    # Impersonificazione di brand terzi noti (DHL, Poste, PayPal, ...): usa
    # (nome visualizzato, dominio) annidati nel forward, non filtrati per
    # dominio autorizzato dato che qui interessa il nome dichiarato, non solo
    # se il dominio è esterno.
    brand_impersonation_matches = find_brand_impersonation(parsed.quoted_senders)

    verdict = compute_verdict(
        rspamd_result,
        vt_result,
        lookalike_matches,
        parsed.auth_results,
        config.scoring,
        domain_age_result=domain_age_result,
        urlhaus_result=urlhaus_result,
        safebrowsing_result=safebrowsing_result,
        brand_impersonation_matches=brand_impersonation_matches,
        quoted_from_domains=parsed.quoted_from_domains,
        quoted_reply_to_domains=parsed.quoted_reply_to_domains,
    )

    response_sent = False
    error = None
    if parsed.reply_to_address:
        try:
            send_verdict_email(
                config.smtp,
                parsed.reply_to_address,
                parsed.subject,
                verdict,
                original_message_id=parsed.raw_headers.get("Message-ID"),
            )
            response_sent = True
        except Exception as exc:  # noqa: BLE001 - non deve interrompere il logging
            logger.exception("Invio risposta SMTP fallito per UID %s", uid)
            error = f"invio SMTP fallito: {exc}"
    else:
        error = "impossibile determinare l'indirizzo del mittente/forwarder"
        logger.error("UID %s: %s", uid, error)

    log_entry = {
        "message_uid": uid,
        "from_address": parsed.from_address,
        "reply_to_address": parsed.reply_to_address,
        "subject": parsed.subject,
        "risk_score": verdict.risk_score,
        "verdict": verdict.label,
        "reasons": verdict.reasons,
        "lookalike": {
            "matches": [
                {
                    "suspect_domain": m.suspect_domain,
                    "legitimate_domain": m.legitimate_domain,
                    "distance": m.distance,
                    "similarity_ratio": m.similarity_ratio,
                    "reason": m.reason,
                }
                for m in lookalike_matches
            ]
        },
        "virustotal": vt_result,
        "urlhaus": urlhaus_result,
        "safebrowsing": safebrowsing_result,
        "rspamd": rspamd_result,
        "domain_age": domain_age_result,
        "brand_impersonation": {
            "matches": [
                {
                    "claimed_brand": m.claimed_brand,
                    "sender_domain": m.sender_domain,
                    "legitimate_domains": m.legitimate_domains,
                }
                for m in brand_impersonation_matches
            ]
        },
        "external_candidate_domains": external_candidate_domains,
        "quoted_from_domains": parsed.quoted_from_domains,
        "quoted_reply_to_domains": parsed.quoted_reply_to_domains,
        "auth": parsed.auth_results,
        "response_sent": response_sent,
        "error": error,
    }

    db.insert_analysis_log(config.storage.sqlite_path, log_entry)
    append_analysis_jsonl(config.storage.analysis_jsonl_path, log_entry)
    return log_entry


def run_once(config: Config) -> int:
    db.init_db(config.storage.sqlite_path)
    processed_count = 0

    allowed_forwarder_domains = [
        row["domain"] for row in db.list_allowed_forwarder_domains(config.storage.sqlite_path)
    ]
    if not allowed_forwarder_domains:
        logger.warning(
            "Nessun dominio autorizzato configurato: tutte le email in arrivo verranno "
            "ignorate. Aggiungine almeno uno dall'interfaccia web (sezione 'Domini autorizzati')."
        )

    try:
        with ImapSession(config.imap) as session:
            for uid, raw_bytes, message in session.fetch_unprocessed():
                try:
                    entry = process_one_message(
                        uid, raw_bytes, message, config, allowed_forwarder_domains
                    )
                    session.delete_message(uid)
                    processed_count += 1
                    logger.info(
                        "UID %s elaborato: verdetto=%s score=%.2f",
                        uid,
                        entry["verdict"],
                        entry["risk_score"],
                    )
                except Exception:  # noqa: BLE001 - isola l'errore al singolo messaggio
                    logger.exception("Errore imprevisto elaborando UID %s", uid)
                    session.mark_seen_only(uid)

            session.purge_sent_folder()
    except ImapError:
        logger.exception("Impossibile completare il ciclo di polling IMAP")
        return 1

    logger.info("Ciclo completato: %d messaggi elaborati", processed_count)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SpamBox worker - analisi email inoltrate")
    parser.add_argument("--config", default=None, help="percorso file config.yaml")
    args = parser.parse_args()

    config = load_config(args.config)
    setup_app_logging(config.storage.app_log_path)
    return run_once(config)


if __name__ == "__main__":
    sys.exit(main())
