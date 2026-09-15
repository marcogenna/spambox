"""Motore di scoring: combina rspamd, VirusTotal, URLhaus, lookalike, età del
dominio (RDAP) e auth (SPF/DKIM/DMARC) in un punteggio di rischio 0-10 e un
verdetto testuale in italiano.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from spambox.config import ScoringConfig
from spambox.worker.analyzers.brand_impersonation import BrandImpersonationMatch
from spambox.worker.analyzers.lookalike import LookalikeMatch


@dataclass
class Verdict:
    risk_score: float
    label: str
    reasons: list[str] = field(default_factory=list)


# Traduzione in linguaggio semplice dei simboli Rspamd più comuni: il nome
# tecnico della regola (es. "FUZZY_DENIED") non deve mai arrivare all'utente
# finale nella risposta via email. Il nome originale resta comunque
# disponibile nei log strutturati (SQLite/JSONL) per chi deve fare audit.
RSPAMD_SYMBOL_TRANSLATIONS: dict[str, str] = {
    "FUZZY_DENIED": "Il contenuto del messaggio è molto simile a campagne di spam già note",
    "BAYES_SPAM": "Il testo del messaggio ha caratteristiche tipiche dello spam",
    "PHISHING": "Il messaggio contiene elementi tipici di un tentativo di phishing",
    "HFILTER_HOSTNAME_UNKNOWN": "Il server che ha inviato il messaggio non risulta identificabile in modo affidabile",
    "URI_COUNT_ODD": "Il messaggio contiene un numero insolito di link",
    "MANY_INVISIBLE_PARTS": "Il messaggio nasconde parti di contenuto non visibili, tecnica usata per ingannare i filtri antispam",
    "FORGED_SENDER": "L'indirizzo del mittente sembra falsificato",
    "SPOOF_DISPLAY_NAME": "Il nome visualizzato del mittente non corrisponde al suo indirizzo email reale",
    "DMARC_POLICY_REJECT": "Il dominio del mittente non supera i controlli di sicurezza email (DMARC)",
    "DMARC_POLICY_QUARANTINE": "Il dominio del mittente non supera pienamente i controlli di sicurezza email (DMARC)",
    "R_SPF_FAIL": "Il server che ha inviato il messaggio non è autorizzato per quel dominio (SPF)",
    "R_DKIM_REJECT": "La firma digitale di autenticità del messaggio non è valida (DKIM)",
    "MIME_SUSPECT_EXE": "Il messaggio contiene un allegato potenzialmente pericoloso",
}


def _translate_rspamd_reason(symbol_name: str) -> str:
    return RSPAMD_SYMBOL_TRANSLATIONS.get(
        symbol_name, "Il filtro antispam ha rilevato un elemento sospetto nel messaggio"
    )


def _rspamd_component(rspamd_result: dict[str, Any]) -> tuple[float, list[str]]:
    if not rspamd_result.get("available"):
        return 0.0, []
    score = float(rspamd_result.get("score", 0.0))
    required = rspamd_result.get("required_score") or 15.0
    normalized = min(max(score / required, 0.0), 1.0) * 10
    reasons: list[str] = []
    if rspamd_result.get("action") in ("reject", "add header", "rewrite subject"):
        top_symbols = sorted(
            rspamd_result.get("symbols_detail", {}).items(),
            key=lambda kv: kv[1].get("score", 0) or 0,
            reverse=True,
        )[:3]
        seen_reasons = set()
        for name, sym in top_symbols:
            if (sym.get("score") or 0) > 0:
                reason = _translate_rspamd_reason(name)
                if reason not in seen_reasons:
                    seen_reasons.add(reason)
                    reasons.append(reason)
    return normalized, reasons


def _virustotal_component(vt_result: dict[str, Any]) -> tuple[float, list[str], bool]:
    if not vt_result.get("available"):
        return 0.0, [], False

    max_ratio = 0.0
    has_malicious = False
    url_malicious = url_suspicious = file_malicious = file_suspicious = False

    for item in vt_result.get("urls", []):
        if item.get("status") == "malicious":
            url_malicious = True
            has_malicious = True
            total = item.get("total_engines") or 1
            max_ratio = max(max_ratio, item.get("malicious_count", 0) / total)
        elif item.get("status") == "suspicious":
            url_suspicious = True
            max_ratio = max(max_ratio, 0.4)

    for item in vt_result.get("files", []):
        if item.get("status") == "malicious":
            file_malicious = True
            has_malicious = True
            total = item.get("total_engines") or 1
            max_ratio = max(max_ratio, item.get("malicious_count", 0) / total)
        elif item.get("status") == "suspicious":
            file_suspicious = True
            max_ratio = max(max_ratio, 0.4)

    reasons: list[str] = []
    if url_malicious:
        reasons.append(
            "Uno o più link contenuti nel messaggio risultano segnalati come malevoli su VirusTotal"
        )
    if url_suspicious:
        reasons.append("Uno o più link risultano sospetti secondo VirusTotal")
    if file_malicious:
        reasons.append(
            "Uno o più allegati corrispondono a file già riconosciuti come malevoli su VirusTotal"
        )
    if file_suspicious:
        reasons.append("Uno o più allegati risultano sospetti secondo VirusTotal")
    if vt_result.get("quota_exceeded"):
        reasons.append(
            "Attenzione: la quota dell'API VirusTotal è stata superata, alcuni controlli potrebbero essere incompleti"
        )

    return min(max_ratio, 1.0) * 10, reasons, has_malicious


def _lookalike_component(matches: list[LookalikeMatch]) -> tuple[float, list[str]]:
    if not matches:
        return 0.0, []
    reasons = [m.reason for m in matches]
    return 10.0, reasons


def _brand_impersonation_component(matches: list[BrandImpersonationMatch]) -> tuple[float, list[str]]:
    if not matches:
        return 0.0, []
    reasons = [
        (
            f"Il messaggio si presenta come '{m.claimed_brand.upper()}' ma il mittente "
            f"reale ('{m.sender_domain}') non ha nulla a che vedere con quell'azienda: "
            "tecnica tipica delle truffe che imitano corrieri, banche o servizi noti"
        )
        for m in matches
    ]
    return 10.0, reasons


def _reply_to_mismatch_component(
    quoted_from_domains: list[str], quoted_reply_to_domains: list[str]
) -> tuple[float, list[str], bool]:
    """From legittimo ma Reply-To su un dominio scorrelato: tecnica comune per
    dirottare le risposte (o una "verifica identità") verso l'attaccante
    mantenendo un mittente visibile credibile (es. From su un dominio
    aziendale vero, Reply-To su un provider PEC/webmail generico non
    collegato a quell'azienda)."""
    if not quoted_from_domains or not quoted_reply_to_domains:
        return 0.0, [], False

    mismatched = [
        reply_domain
        for reply_domain in quoted_reply_to_domains
        if not any(
            reply_domain == from_domain or reply_domain.endswith("." + from_domain)
            for from_domain in quoted_from_domains
        )
    ]
    if not mismatched:
        return 0.0, [], False

    reasons = [
        f"Le risposte a questo messaggio verrebbero inviate a '{reply_domain}', un dominio "
        f"diverso dal mittente dichiarato ('{quoted_from_domains[0]}'): tecnica comune per "
        "dirottare le risposte verso chi ha inviato la truffa"
        for reply_domain in mismatched
    ]
    return 10.0, reasons, True


def _domain_age_component(domain_age_result: dict[str, Any]) -> tuple[float, list[str]]:
    if not domain_age_result.get("available") or not domain_age_result.get("is_recent"):
        return 0.0, []
    age_days = domain_age_result.get("age_days", 0)
    reason = (
        f"Il dominio del mittente è stato registrato molto di recente ({age_days} giorni fa): "
        "è un segnale tipico delle campagne di phishing, che spesso usano domini appena creati"
    )
    return 10.0, [reason]


def _urlhaus_component(urlhaus_result: dict[str, Any]) -> tuple[float, list[str], bool]:
    if not urlhaus_result.get("available"):
        return 0.0, [], False

    has_malicious = any(item.get("status") == "malicious" for item in urlhaus_result.get("urls", []))
    reasons: list[str] = []
    if has_malicious:
        reasons.append(
            "Uno o più link contenuti nel messaggio sono presenti nella lista di URL malevoli di URLhaus"
        )
    if urlhaus_result.get("quota_exceeded"):
        reasons.append(
            "Attenzione: la quota dell'API URLhaus è stata superata, alcuni controlli potrebbero essere incompleti"
        )
    return (10.0 if has_malicious else 0.0), reasons, has_malicious


THREAT_TYPE_TRANSLATIONS: dict[str, str] = {
    "SOCIAL_ENGINEERING": "phishing",
    "MALWARE": "malware",
    "UNWANTED_SOFTWARE": "software indesiderato",
    "POTENTIALLY_HARMFUL_APPLICATION": "applicazione potenzialmente dannosa",
}


def _safebrowsing_component(safebrowsing_result: dict[str, Any]) -> tuple[float, list[str], bool]:
    if not safebrowsing_result.get("available"):
        return 0.0, [], False

    matches = safebrowsing_result.get("matches", [])
    has_malicious = bool(matches)
    reasons: list[str] = []
    if has_malicious:
        threat_labels = sorted({
            THREAT_TYPE_TRANSLATIONS.get(m.get("threat_type"), "minaccia")
            for m in matches
        })
        reasons.append(
            "Uno o più link sono segnalati da Google Safe Browsing come pericolosi ("
            + ", ".join(threat_labels) + ")"
        )
    if safebrowsing_result.get("quota_exceeded"):
        reasons.append(
            "Attenzione: la quota dell'API Google Safe Browsing è stata superata, "
            "alcuni controlli potrebbero essere incompleti"
        )
    return (10.0 if has_malicious else 0.0), reasons, has_malicious


AUTH_FAILURE_MESSAGES: dict[str, str] = {
    "spf": "Il server che ha inviato il messaggio non è autorizzato per quel dominio (controllo SPF non superato)",
    "dkim": "Non è stato possibile verificare l'autenticità del messaggio (controllo DKIM non superato)",
    "dmarc": "Il dominio del mittente non supera i controlli di sicurezza email (controllo DMARC non superato)",
}


def _auth_component(auth_results: dict[str, str]) -> tuple[float, list[str]]:
    if not auth_results:
        return 0.0, []
    failures = [k for k, v in auth_results.items() if v not in ("pass", "none")]
    if not failures:
        return 0.0, []
    reasons = [
        AUTH_FAILURE_MESSAGES.get(f, f"Controllo di sicurezza email '{f.upper()}' non superato")
        for f in failures
    ]
    return min(len(failures) / 3, 1.0) * 10, reasons


def compute_verdict(
    rspamd_result: dict[str, Any],
    virustotal_result: dict[str, Any],
    lookalike_matches: list[LookalikeMatch],
    auth_results: dict[str, str],
    config: ScoringConfig,
    domain_age_result: dict[str, Any] | None = None,
    urlhaus_result: dict[str, Any] | None = None,
    safebrowsing_result: dict[str, Any] | None = None,
    brand_impersonation_matches: list[BrandImpersonationMatch] | None = None,
    quoted_from_domains: list[str] | None = None,
    quoted_reply_to_domains: list[str] | None = None,
) -> Verdict:
    rspamd_score, rspamd_reasons = _rspamd_component(rspamd_result)
    vt_score, vt_reasons, vt_has_malicious = _virustotal_component(virustotal_result)
    lookalike_score, lookalike_reasons = _lookalike_component(lookalike_matches)
    auth_score, auth_reasons = _auth_component(auth_results)
    domain_age_score, domain_age_reasons = _domain_age_component(domain_age_result or {})
    urlhaus_score, urlhaus_reasons, urlhaus_has_malicious = _urlhaus_component(urlhaus_result or {})
    safebrowsing_score, safebrowsing_reasons, safebrowsing_has_malicious = _safebrowsing_component(
        safebrowsing_result or {}
    )
    brand_score, brand_reasons = _brand_impersonation_component(brand_impersonation_matches or [])
    reply_to_score, reply_to_reasons, reply_to_mismatch = _reply_to_mismatch_component(
        quoted_from_domains or [], quoted_reply_to_domains or []
    )

    total = (
        rspamd_score * config.weight_rspamd
        + vt_score * config.weight_virustotal
        + lookalike_score * config.weight_lookalike
        + auth_score * config.weight_auth_failure
        + domain_age_score * config.weight_domain_age
        + urlhaus_score * config.weight_urlhaus
        + safebrowsing_score * config.weight_safebrowsing
        + brand_score * config.weight_brand_impersonation
        + reply_to_score * config.weight_reply_to_mismatch
    )

    # Due livelli di floor, per non annacquare rilevazioni certe nella media
    # pesata tra 9 componenti:
    #
    # 1) Rilevazioni CONFERMATE da un servizio di threat-intel dedicato
    #    (VirusTotal, URLhaus, Google Safe Browsing = più motori/vendor che
    #    hanno già classificato quell'URL/hash come malevolo): una sola di
    #    queste basta da sola per "Altamente pericolosa", non serve conferma
    #    incrociata.
    # 2) Indizi EURISTICI (lookalike, impersonificazione di brand, Reply-To
    #    dirottato su un dominio diverso dal From, dominio registrato di
    #    recente, rspamd che classifica come reject): forti ma non una prova
    #    diretta presa singolarmente, quindi floor a "Sospetta"; se se ne
    #    accumulano almeno due si sale comunque a "pericolosa".
    confirmed_malicious = [vt_has_malicious, urlhaus_has_malicious, safebrowsing_has_malicious]
    heuristic_signals = [
        bool(lookalike_matches),
        bool(brand_impersonation_matches),
        reply_to_mismatch,
        bool((domain_age_result or {}).get("is_recent")),
        rspamd_result.get("action") == "reject",
    ]

    if any(confirmed_malicious):
        total = max(total, config.threshold_pericolosa)
    elif any(heuristic_signals):
        total = max(total, config.threshold_sospetta)
        if sum(heuristic_signals) >= 2:
            total = max(total, config.threshold_pericolosa)

    total = round(min(total, 10.0), 2)

    if total >= config.threshold_pericolosa:
        label = "Altamente pericolosa"
    elif total >= config.threshold_sospetta:
        label = "Sospetta"
    else:
        label = "Sicura"

    combined = (
        brand_reasons + reply_to_reasons + lookalike_reasons + vt_reasons + urlhaus_reasons
        + safebrowsing_reasons + domain_age_reasons + auth_reasons + rspamd_reasons
    )
    reasons = list(dict.fromkeys(combined))  # dedup preservando l'ordine
    if not reasons:
        reasons.append("Nessun elemento di rischio significativo rilevato dalle analisi automatiche")

    return Verdict(risk_score=total, label=label, reasons=reasons)
