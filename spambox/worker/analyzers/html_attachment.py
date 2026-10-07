"""Rilevazione di pagine di phishing per il furto di credenziali allegate
come file HTML (invece che linkate), tecnica nota come "HTML smuggling":
un modulo di login clonato (VPN aziendale, webmail, Office 365...) spedito
come allegato per evitare i controlli sui link e sull'hash — ogni campagna
genera un file leggermente diverso, quindi VirusTotal (che verifica solo
l'hash SHA256, senza analisi di contenuto) non lo riconosce mai come noto.

Qui si applica un'euristica statica sul contenuto HTML/JS dell'allegato:
un campo password combinato con l'invio dei dati verso un servizio esterno
tipico dell'esfiltrazione "usa e getta" (bot Telegram, webhook pubblici,
Discord, Pastebin...) è una combinazione che non ha alcuna ragione
legittima di comparire in un allegato email.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from spambox.worker.mime_parser import Attachment

_PASSWORD_FIELD_RE = re.compile(r"""<input[^>]+type\s*=\s*["']?password["']?""", re.IGNORECASE)

# Endpoint pubblici usati per esfiltrare dati rubati senza dover gestire
# un server proprio: comparire hardcoded dentro un allegato HTML non ha
# alcun uso legittimo.
_EXFIL_ENDPOINT_RE = re.compile(
    r"""api\.telegram\.org|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com|
        webhook\.site|pastebin\.com/api|formspree\.io|script\.google\.com""",
    re.IGNORECASE | re.VERBOSE,
)


# Redirect automatico verso un sito esterno (meta refresh o JavaScript):
# un allegato HTML che appena aperto rimanda altrove è un "redirector", usato
# per nascondere il link di phishing dai controlli sul corpo del messaggio.
_META_REFRESH_RE = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*url\s*=\s*["']?(https?://[^"'>\s]+)""",
    re.IGNORECASE,
)
_JS_REDIRECT_RE = re.compile(
    r"""location(?:\.href\s*=|\.replace\s*\(|\.assign\s*\()\s*["'](https?://[^"']+)""",
    re.IGNORECASE,
)


@dataclass
class HtmlAttachmentPhishingMatch:
    filename: str
    reason: str


def find_html_attachment_phishing(
    attachments: list[Attachment],
) -> list[HtmlAttachmentPhishingMatch]:
    matches: list[HtmlAttachmentPhishingMatch] = []
    for attachment in attachments:
        content = attachment.text_content
        if not content:
            continue

        redirect = _META_REFRESH_RE.search(content) or _JS_REDIRECT_RE.search(content)
        if redirect:
            matches.append(
                HtmlAttachmentPhishingMatch(
                    filename=attachment.filename,
                    reason=(
                        f"L'allegato '{attachment.filename}' è una pagina HTML che, appena aperta, "
                        "rimanda automaticamente a un sito esterno: tecnica tipica del phishing "
                        "per nascondere il vero indirizzo dai controlli sul testo dell'email"
                    ),
                )
            )
            continue

        has_password_field = bool(_PASSWORD_FIELD_RE.search(content))
        exfil_endpoint = _EXFIL_ENDPOINT_RE.search(content)

        if has_password_field and exfil_endpoint:
            matches.append(
                HtmlAttachmentPhishingMatch(
                    filename=attachment.filename,
                    reason=(
                        f"L'allegato '{attachment.filename}' è una pagina HTML con un campo "
                        "password che invia i dati inseriti a un servizio esterno "
                        f"({exfil_endpoint.group(0)}): tecnica tipica delle pagine di "
                        "phishing per il furto di credenziali spedite come allegato "
                        "invece che come link"
                    ),
                )
            )
    return matches
