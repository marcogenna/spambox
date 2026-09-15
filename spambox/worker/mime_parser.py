"""Parsing MIME dei messaggi scaricati via IMAP: header, corpo, URL, allegati."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email.message import Message
from email.utils import getaddresses, parseaddr
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

URL_RE = re.compile(
    r"""(?xi)
    \b
    (?:https?://|www\.)
    [^\s<>"'\]\)]+
    """
)

AUTH_RESULT_RE = re.compile(r"(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)

# Etichette usate dai client email per introdurre l'header "From"/"Reply-To"
# di un messaggio inoltrato in-line (italiano, inglese, ed alcune lingue
# comuni), usate per risalire al mittente ORIGINALE (e a chi riceverebbe le
# risposte) dentro un forward, invece del semplice From del messaggio come
# ricevuto (che nei forward e' l'indirizzo di chi ha inoltrato, non quello
# sospetto da controllare). Tenute separate (non unite in un'unica regex)
# perche' un From legittimo con un Reply-To su un dominio diverso e' di per
# se' un segnale di phishing, indipendentemente dal riconoscere un brand: va
# quindi possibile confrontarli, non solo raccoglierli insieme.
_FORWARD_FROM_LINE_RE = re.compile(
    r"^\s*>*\s*(?:From|Da|De|Von|Van)\s*:\s*(.*?)<?([\w.+-]+@[\w.-]+\.\w+)>?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_FORWARD_REPLYTO_LINE_RE = re.compile(
    r"^\s*>*\s*(?:Reply-To|Rispondi\s*a)\s*:\s*(.*?)<?([\w.+-]+@[\w.-]+\.\w+)>?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_MAILTO_RE = re.compile(r"mailto:([\w.+-]+@[\w.-]+\.\w+)", re.IGNORECASE)

# Wrapper di redirect/tracking usati per nascondere la vera destinazione di
# un link di phishing dietro un dominio "affidabile" (es. Google): (host che
# compare nel link, parametro della query string che contiene l'URL reale).
_REDIRECT_WRAPPERS: list[tuple[str, str]] = [
    ("google.", "q"),
    ("l.facebook.com", "u"),
    ("linkedin.com", "url"),
    ("safelinks.protection.outlook.com", "url"),
]


def _unwrap_redirect_url(url: str) -> Optional[str]:
    """Se l'URL è un redirect/tracking noto (es. google.com/url?q=...),
    restituisce l'URL di destinazione reale codificato al suo interno;
    altrimenti None. Serve perché VirusTotal/URLhaus vanno interrogati sulla
    destinazione vera, non sul dominio "innocente" del wrapper."""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        for wrapper_host, param in _REDIRECT_WRAPPERS:
            if wrapper_host in host:
                target = parse_qs(parsed.query).get(param)
                if target and target[0].startswith(("http://", "https://")):
                    return unquote(target[0])
    except ValueError:
        pass
    return None


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    is_inline: bool = False


@dataclass
class ParsedMessage:
    from_address: str
    from_domain: str
    reply_to_address: str
    subject: str
    date: Optional[str]
    text_body: str
    html_body: str
    urls: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    auth_results: dict[str, str] = field(default_factory=dict)
    raw_headers: dict[str, str] = field(default_factory=dict)
    quoted_sender_domains: list[str] = field(default_factory=list)
    quoted_senders: list[tuple[str, str]] = field(default_factory=list)  # (display_name, domain)
    quoted_from_domains: list[str] = field(default_factory=list)
    quoted_reply_to_domains: list[str] = field(default_factory=list)


def _strip_html_tags(html: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _extract_urls(*texts: str) -> list[str]:
    found: list[str] = []
    seen = set()

    def _add(url: str) -> None:
        if url not in seen:
            seen.add(url)
            found.append(url)

    for text in texts:
        if not text:
            continue
        for match in URL_RE.findall(text):
            url = match.rstrip(").,;:!?'\"")
            _add(url)
            unwrapped = _unwrap_redirect_url(url)
            if unwrapped:
                _add(unwrapped)

    return found


def _parse_auth_results(message: Message) -> dict[str, str]:
    results: dict[str, str] = {}
    for header_value in message.get_all("Authentication-Results", []):
        for key, value in AUTH_RESULT_RE.findall(header_value):
            results[key.lower()] = value.lower()
    return results


def _extract_quoted_senders(
    text_body: str, html_body: str, own_domain: str
) -> tuple[list[tuple[str, str]], list[str], list[str]]:
    """Risale a nome visualizzato + dominio dei mittenti ORIGINALI annidati
    dentro un forward, distinguendo From e Reply-To.

    Un forward in-line (Apple Mail, Outlook, ecc.) riporta queste informazioni
    come testo semplice dentro il corpo ("> From: DHL <...>", "Da: ...") e/o
    come link mailto: nell'HTML: nessuno dei due è un header MIME vero, quindi
    vanno estratti dal contenuto. Senza questo, un'analisi basata solo sugli
    header del messaggio come ricevuto controllerebbe il dominio di chi ha
    inoltrato (fidato) invece del mittente esterno sospetto, e non potrebbe
    rilevare né l'impersonificazione di un brand (es. "From: DHL <...@dominio-a-caso.ru>")
    né un Reply-To dirottato su un dominio diverso dal From (es. From su un
    dominio aziendale vero ma Reply-To su un provider PEC/webmail generico
    non collegato a quell'azienda: tecnica comune per dirottare le risposte
    verso l'attaccante mantenendo un mittente visibile credibile).

    Restituisce (tutti i mittenti trovati, domini visti in righe From, domini
    visti in righe Reply-To) — i primi due sono usati per lookalike/età
    dominio/brand, il terzo per il confronto From-vs-Reply-To.
    """
    found: list[tuple[str, str]] = []
    from_domains: list[str] = []
    reply_to_domains: list[str] = []
    seen = set()

    def _add(display_name: str, domain: str) -> None:
        if domain and domain != own_domain and (display_name, domain) not in seen:
            seen.add((display_name, domain))
            found.append((display_name, domain))

    for text in (text_body, html_body):
        if not text:
            continue
        for display_name, email_addr in _FORWARD_FROM_LINE_RE.findall(text):
            domain = _domain_from_address(email_addr.lower())
            _add(display_name.strip().strip("<>\"'").strip(), domain)
            if domain and domain != own_domain and domain not in from_domains:
                from_domains.append(domain)
        for display_name, email_addr in _FORWARD_REPLYTO_LINE_RE.findall(text):
            domain = _domain_from_address(email_addr.lower())
            _add(display_name.strip().strip("<>\"'").strip(), domain)
            if domain and domain != own_domain and domain not in reply_to_domains:
                reply_to_domains.append(domain)
        for email_addr in _MAILTO_RE.findall(text):
            _add("", _domain_from_address(email_addr.lower()))

    return found, from_domains, reply_to_domains


def _domain_from_address(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower()


def _reply_target(message: Message) -> str:
    """Determina l'indirizzo a cui rispondere con il verdetto.

    Si privilegia Reply-To se presente (alcuni client di forward lo valorizzano),
    altrimenti si usa il mittente (From) del messaggio così come ricevuto nella
    mailbox dedicata: per un forward "inline" standard coincide con l'indirizzo
    di chi ha inoltrato l'email.
    """
    reply_to = message.get("Reply-To", "")
    if reply_to:
        _, addr = parseaddr(reply_to)
        if addr:
            return addr
    _, addr = parseaddr(message.get("From", ""))
    return addr


def parse_message(raw_bytes: bytes, message: Message) -> ParsedMessage:
    _, from_addr = parseaddr(message.get("From", ""))
    from_addr = from_addr.lower()
    reply_target = _reply_target(message).lower()
    subject = message.get("Subject", "(nessun oggetto)")
    date = message.get("Date")

    text_body = ""
    html_body = ""
    attachments: list[Attachment] = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")

            if part.is_multipart():
                continue

            if "attachment" in disposition or part.get_filename():
                payload = part.get_payload(decode=True) or b""
                filename = part.get_filename() or "allegato_senza_nome"
                attachments.append(
                    Attachment(
                        filename=filename,
                        content_type=content_type,
                        size=len(payload),
                        sha256=hashlib.sha256(payload).hexdigest(),
                        is_inline="inline" in disposition.lower(),
                    )
                )
                continue

            if content_type == "text/plain" and not text_body:
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                text_body += payload.decode(charset, errors="replace")
            elif content_type == "text/html" and not html_body:
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                html_body += payload.decode(charset, errors="replace")
    else:
        payload = message.get_payload(decode=True) or b""
        charset = message.get_content_charset() or "utf-8"
        decoded = payload.decode(charset, errors="replace")
        if message.get_content_type() == "text/html":
            html_body = decoded
        else:
            text_body = decoded

    plain_from_html = _strip_html_tags(html_body) if html_body else ""
    urls = _extract_urls(text_body, html_body)
    from_domain = _domain_from_address(from_addr)
    quoted_senders, quoted_from_domains, quoted_reply_to_domains = _extract_quoted_senders(
        text_body, html_body, from_domain
    )
    quoted_sender_domains = list(dict.fromkeys(domain for _, domain in quoted_senders))

    raw_headers = {k: v for k, v in message.items()}

    return ParsedMessage(
        from_address=from_addr,
        from_domain=from_domain,
        reply_to_address=reply_target,
        subject=subject,
        date=date,
        text_body=text_body or plain_from_html,
        html_body=html_body,
        urls=urls,
        attachments=attachments,
        auth_results=_parse_auth_results(message),
        raw_headers=raw_headers,
        quoted_sender_domains=quoted_sender_domains,
        quoted_senders=quoted_senders,
        quoted_from_domains=quoted_from_domains,
        quoted_reply_to_domains=quoted_reply_to_domains,
    )
