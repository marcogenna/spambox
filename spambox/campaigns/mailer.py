"""Invio delle email di campagna (phishing simulato) e della risposta di
rinforzo positivo quando un dipendente segnala correttamente il test.
"""
from __future__ import annotations

import logging
import secrets
import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid, parseaddr

from spambox.config import SmtpConfig

logger = logging.getLogger("spambox.campaigns")

REINFORCEMENT_TEMPLATE = """Ottimo lavoro!

Ciao,
l'email che hai appena inoltrato ("{original_subject}") era in realtà un
test di sicurezza simulato, organizzato dalla tua azienda per allenare il
riconoscimento delle email di phishing.

Hai fatto esattamente la cosa giusta: l'hai riconosciuta come sospetta e
l'hai segnalata invece di cliccare sui link o rispondere. Continua così.

---
Questo è un messaggio automatico, non serve rispondere.
"""


def generate_token() -> str:
    return secrets.token_urlsafe(24)


def _send(config: SmtpConfig, to_address: str, subject: str, body: str, html: bool = False) -> None:
    msg = MIMEText(body, "html" if html else "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = config.from_address
    msg["To"] = to_address
    # Impostati esplicitamente perché Message-ID e' tra gli header coperti
    # dalla firma DKIM: se un hop successivo alla firma lo aggiunge o lo
    # modifica, la verifica DKIM fallisce lato destinatario anche con chiave
    # DNS corretta (vedi spambox/worker/responder.py per il caso originale).
    msg["Date"] = formatdate(localtime=True)
    _, from_email = parseaddr(config.from_address)
    from_domain = from_email.rsplit("@", 1)[-1] if "@" in from_email else None
    msg["Message-ID"] = make_msgid(domain=from_domain)

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
    finally:
        try:
            server.quit()
        except smtplib.SMTPException:
            pass


def send_campaign_email(
    smtp_config: SmtpConfig,
    to_address: str,
    subject: str,
    body_html: str,
    sender_display_name: str,
    link: str,
) -> None:
    """Invia una email di campagna a un singolo destinatario, sostituendo il
    placeholder {{link}} nel corpo con il link di tracciamento univoco."""
    body = body_html.replace("{{link}}", link)
    original_from = smtp_config.from_address
    _, from_email = parseaddr(original_from)
    display_from = f"{sender_display_name} <{from_email}>" if from_email else original_from
    override_config = SmtpConfig(**{**smtp_config.__dict__, "from_address": display_from})
    _send(override_config, to_address, subject, body, html=True)
    logger.info("Email di campagna inviata a %s", to_address)


def send_reinforcement_email(smtp_config: SmtpConfig, to_address: str, original_subject: str) -> None:
    """Risposta di rinforzo positivo quando un dipendente segnala
    correttamente (a SpamBox) un'email di campagna invece di cliccarla."""
    body = REINFORCEMENT_TEMPLATE.format(original_subject=original_subject or "(nessun oggetto)")
    _send(smtp_config, to_address, "Bravo/a! Hai superato un test di sicurezza simulato", body)
    logger.info("Risposta di rinforzo positivo inviata a %s", to_address)
