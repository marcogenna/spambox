"""Composizione e invio via SMTP della risposta automatica in italiano."""
from __future__ import annotations

import logging
import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid, parseaddr

from spambox.config import SmtpConfig
from spambox.worker.verdict import Verdict

logger = logging.getLogger("spambox.responder")

TEMPLATE = """Verdetto: {label}

Ciao,
abbiamo controllato l'email che hai inoltrato (oggetto originale: "{original_subject}") e questo è il risultato.

{summary}

Livello di rischio: {score:.1f} su 10

Cosa abbiamo notato:
{reasons}

Cosa fare adesso:
{consiglio}

---
Questo è un messaggio automatico, non serve rispondere.
Per qualsiasi altro dubbio, inoltra pure altre email sospette a questo stesso indirizzo.
"""

SUMMARY_BY_LABEL = {
    "Sicura": "Non abbiamo trovato elementi di rischio significativi: sembra un'email legittima.",
    "Sicura_con_dettagli": (
        "Non abbiamo trovato elementi di rischio tali da considerarla pericolosa, "
        "anche se qualche dettaglio minore è comunque riportato qui sotto."
    ),
    "Sospetta": "Abbiamo trovato alcuni elementi sospetti: ti consigliamo di fare attenzione.",
    "Altamente pericolosa": "Abbiamo trovato elementi che indicano con buona probabilità un tentativo di truffa o phishing.",
}

NO_RISK_FOUND_REASON = "Nessun elemento di rischio significativo rilevato dalle analisi automatiche"

ADVICE_BY_LABEL = {
    "Sicura": "Nessuna azione particolare richiesta, ma mantieni sempre prudenza con link e allegati inattesi.",
    "Sospetta": "Evita di cliccare sui link e non fornire dati personali finché non sei certo della fonte.",
    "Altamente pericolosa": "Non cliccare sui link e non aprire gli allegati. In caso di dubbi contatta il supporto IT.",
}


def build_message(verdict: Verdict, original_subject: str) -> str:
    reasons_block = "\n".join(f"- {r}" for r in verdict.reasons)

    has_real_reasons = verdict.reasons and verdict.reasons != [NO_RISK_FOUND_REASON]
    if verdict.label == "Sicura" and has_real_reasons:
        summary = SUMMARY_BY_LABEL["Sicura_con_dettagli"]
    else:
        summary = SUMMARY_BY_LABEL.get(verdict.label, SUMMARY_BY_LABEL["Sospetta"])
    advice = ADVICE_BY_LABEL.get(verdict.label, ADVICE_BY_LABEL["Sospetta"])
    return TEMPLATE.format(
        label=verdict.label,
        original_subject=original_subject or "(nessun oggetto)",
        summary=summary,
        score=verdict.risk_score,
        reasons=reasons_block,
        consiglio=advice,
    )


def _truncate(text: str, max_len: int = 60) -> str:
    text = text or ""
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def send_verdict_email(
    config: SmtpConfig,
    to_address: str,
    original_subject: str,
    verdict: Verdict,
    original_message_id: str | None = None,
) -> None:
    body = build_message(verdict, original_subject)
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = f'Risultato analisi: {verdict.label} - "{_truncate(original_subject)}"'
    msg["From"] = config.from_address
    msg["To"] = to_address
    # Impostati esplicitamente (invece di lasciarli aggiungere da un relay a
    # valle) perché Message-ID e' tra gli header coperti dalla firma DKIM: se
    # un hop successivo alla firma lo aggiunge o lo modifica, la verifica
    # DKIM fallisce lato destinatario anche con chiave DNS corretta.
    msg["Date"] = formatdate(localtime=True)
    _, from_email = parseaddr(config.from_address)
    from_domain = from_email.rsplit("@", 1)[-1] if "@" in from_email else None
    msg["Message-ID"] = make_msgid(domain=from_domain)
    if original_message_id:
        # Permette al client email del destinatario di raggruppare la
        # risposta nella stessa conversazione dell'email che ha inoltrato.
        msg["In-Reply-To"] = original_message_id
        msg["References"] = original_message_id

    if config.use_ssl:
        server = smtplib.SMTP_SSL(config.host, config.port, timeout=config.timeout)
    else:
        server = smtplib.SMTP(config.host, config.port, timeout=config.timeout)

    try:
        if config.use_starttls and not config.use_ssl:
            server.starttls()
        if config.username:
            server.login(config.username, config.password)
        server.sendmail(config.from_address, [to_address], msg.as_string())
        logger.info("Risposta inviata a %s (verdetto=%s)", to_address, verdict.label)
    finally:
        try:
            server.quit()
        except smtplib.SMTPException:
            pass
