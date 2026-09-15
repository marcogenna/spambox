"""Caricamento configurazione SpamBox da file YAML + override da variabili d'ambiente.

Le credenziali non sono mai hardcoded: possono stare nel file YAML (per comodità
in ambienti di sviluppo/test) ma qualunque variabile d'ambiente SPAMBOX_* ha
sempre precedenza, permettendo di tenere config.yaml fuori dal version control
e i segreti reali solo in ambiente (es. systemd EnvironmentFile).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path(
    os.environ.get("SPAMBOX_CONFIG", "config/config.yaml")
)


def _env_override(value: Any, env_var: str) -> Any:
    return os.environ.get(env_var, value)


@dataclass
class ImapConfig:
    host: str
    port: int
    use_ssl: bool
    username: str
    password: str
    mailbox: str
    sent_mailbox: str
    connect_timeout: int
    max_retries: int
    retry_backoff_seconds: int


@dataclass
class SmtpConfig:
    host: str
    port: int
    use_starttls: bool
    use_ssl: bool
    username: str
    password: str
    from_address: str
    timeout: int


@dataclass
class VirusTotalConfig:
    enabled: bool
    api_key: str
    base_url: str
    requests_per_minute: int
    request_timeout_seconds: int
    max_urls_per_message: int
    max_attachments_per_message: int


@dataclass
class RspamdConfig:
    enabled: bool
    base_url: str
    password: str
    timeout_seconds: int


@dataclass
class LookalikeConfig:
    levenshtein_max_distance: int
    similarity_ratio_threshold: float


@dataclass
class DomainAgeConfig:
    enabled: bool
    base_url: str
    suspicious_if_younger_than_days: int
    request_timeout_seconds: int


@dataclass
class UrlhausConfig:
    enabled: bool
    base_url: str
    auth_key: str
    requests_per_minute: int
    max_urls_per_message: int
    request_timeout_seconds: int


@dataclass
class SafeBrowsingConfig:
    enabled: bool
    base_url: str
    api_key: str
    max_urls_per_message: int
    request_timeout_seconds: int


@dataclass
class ScoringConfig:
    weight_rspamd: float
    weight_virustotal: float
    weight_lookalike: float
    weight_auth_failure: float
    weight_domain_age: float
    weight_urlhaus: float
    weight_safebrowsing: float
    weight_brand_impersonation: float
    weight_reply_to_mismatch: float
    threshold_sospetta: float
    threshold_pericolosa: float


@dataclass
class StorageConfig:
    sqlite_path: str
    analysis_jsonl_path: str
    app_log_path: str


@dataclass
class WebConfig:
    host: str
    port: int
    username: str
    password_sha256: str
    session_secret: str


@dataclass
class Config:
    imap: ImapConfig
    smtp: SmtpConfig
    virustotal: VirusTotalConfig
    rspamd: RspamdConfig
    lookalike: LookalikeConfig
    domain_age: DomainAgeConfig
    urlhaus: UrlhausConfig
    safebrowsing: SafeBrowsingConfig
    scoring: ScoringConfig
    storage: StorageConfig
    web: WebConfig


def load_config(path: str | Path | None = None) -> Config:
    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if not cfg_path.exists():
        raise FileNotFoundError(
            f"File di configurazione non trovato: {cfg_path}. "
            "Copiare config/config.example.yaml in config/config.yaml e valorizzarlo."
        )
    with cfg_path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    imap_raw = raw["imap"]
    smtp_raw = raw["smtp"]
    vt_raw = raw["virustotal"]
    rspamd_raw = raw["rspamd"]
    lookalike_raw = raw["lookalike"]
    domain_age_raw = raw.get("domain_age", {})
    urlhaus_raw = raw.get("urlhaus", {})
    safebrowsing_raw = raw.get("safebrowsing", {})
    scoring_raw = raw["scoring"]
    storage_raw = raw["storage"]
    web_raw = raw["web"]

    imap = ImapConfig(
        host=imap_raw["host"],
        port=int(imap_raw["port"]),
        use_ssl=bool(imap_raw["use_ssl"]),
        username=imap_raw["username"],
        password=_env_override(imap_raw["password"], "SPAMBOX_IMAP_PASSWORD"),
        mailbox=imap_raw["mailbox"],
        sent_mailbox=imap_raw.get("sent_mailbox", "INBOX.Sent"),
        connect_timeout=int(imap_raw["connect_timeout"]),
        max_retries=int(imap_raw["max_retries"]),
        retry_backoff_seconds=int(imap_raw["retry_backoff_seconds"]),
    )
    smtp = SmtpConfig(
        host=smtp_raw["host"],
        port=int(smtp_raw["port"]),
        use_starttls=bool(smtp_raw["use_starttls"]),
        use_ssl=bool(smtp_raw["use_ssl"]),
        username=smtp_raw["username"],
        password=_env_override(smtp_raw["password"], "SPAMBOX_SMTP_PASSWORD"),
        from_address=smtp_raw["from_address"],
        timeout=int(smtp_raw["timeout"]),
    )
    virustotal = VirusTotalConfig(
        enabled=bool(vt_raw["enabled"]),
        api_key=_env_override(vt_raw["api_key"], "SPAMBOX_VT_API_KEY"),
        base_url=vt_raw["base_url"],
        requests_per_minute=int(vt_raw["requests_per_minute"]),
        request_timeout_seconds=int(vt_raw["request_timeout_seconds"]),
        max_urls_per_message=int(vt_raw["max_urls_per_message"]),
        max_attachments_per_message=int(vt_raw["max_attachments_per_message"]),
    )
    rspamd = RspamdConfig(
        enabled=bool(rspamd_raw["enabled"]),
        base_url=rspamd_raw["base_url"],
        password=_env_override(rspamd_raw.get("password", ""), "SPAMBOX_RSPAMD_PASSWORD"),
        timeout_seconds=int(rspamd_raw["timeout_seconds"]),
    )
    lookalike = LookalikeConfig(
        levenshtein_max_distance=int(lookalike_raw["levenshtein_max_distance"]),
        similarity_ratio_threshold=float(lookalike_raw["similarity_ratio_threshold"]),
    )
    domain_age = DomainAgeConfig(
        enabled=bool(domain_age_raw.get("enabled", True)),
        base_url=domain_age_raw.get("base_url", "https://rdap.org"),
        suspicious_if_younger_than_days=int(domain_age_raw.get("suspicious_if_younger_than_days", 30)),
        request_timeout_seconds=int(domain_age_raw.get("request_timeout_seconds", 10)),
    )
    urlhaus = UrlhausConfig(
        enabled=bool(urlhaus_raw.get("enabled", True)),
        base_url=urlhaus_raw.get("base_url", "https://urlhaus-api.abuse.ch/v1"),
        auth_key=_env_override(urlhaus_raw.get("auth_key", ""), "SPAMBOX_URLHAUS_AUTH_KEY"),
        requests_per_minute=int(urlhaus_raw.get("requests_per_minute", 60)),
        max_urls_per_message=int(urlhaus_raw.get("max_urls_per_message", 10)),
        request_timeout_seconds=int(urlhaus_raw.get("request_timeout_seconds", 10)),
    )
    safebrowsing = SafeBrowsingConfig(
        enabled=bool(safebrowsing_raw.get("enabled", True)),
        base_url=safebrowsing_raw.get("base_url", "https://safebrowsing.googleapis.com/v4"),
        api_key=_env_override(safebrowsing_raw.get("api_key", ""), "SPAMBOX_SAFEBROWSING_API_KEY"),
        max_urls_per_message=int(safebrowsing_raw.get("max_urls_per_message", 20)),
        request_timeout_seconds=int(safebrowsing_raw.get("request_timeout_seconds", 10)),
    )
    scoring = ScoringConfig(
        weight_rspamd=float(scoring_raw["weight_rspamd"]),
        weight_virustotal=float(scoring_raw["weight_virustotal"]),
        weight_lookalike=float(scoring_raw["weight_lookalike"]),
        weight_auth_failure=float(scoring_raw["weight_auth_failure"]),
        weight_domain_age=float(scoring_raw.get("weight_domain_age", 0.10)),
        weight_urlhaus=float(scoring_raw.get("weight_urlhaus", 0.15)),
        weight_safebrowsing=float(scoring_raw.get("weight_safebrowsing", 0.15)),
        weight_brand_impersonation=float(scoring_raw.get("weight_brand_impersonation", 0.10)),
        weight_reply_to_mismatch=float(scoring_raw.get("weight_reply_to_mismatch", 0.09)),
        threshold_sospetta=float(scoring_raw["threshold_sospetta"]),
        threshold_pericolosa=float(scoring_raw["threshold_pericolosa"]),
    )
    storage = StorageConfig(
        sqlite_path=storage_raw["sqlite_path"],
        analysis_jsonl_path=storage_raw["analysis_jsonl_path"],
        app_log_path=storage_raw["app_log_path"],
    )
    web = WebConfig(
        host=web_raw["host"],
        port=int(web_raw["port"]),
        username=_env_override(web_raw["username"], "SPAMBOX_WEB_USERNAME"),
        password_sha256=_env_override(
            web_raw["password_sha256"], "SPAMBOX_WEB_PASSWORD_SHA256"
        ),
        session_secret=_env_override(
            web_raw["session_secret"], "SPAMBOX_WEB_SESSION_SECRET"
        ),
    )

    return Config(
        imap=imap,
        smtp=smtp,
        virustotal=virustotal,
        rspamd=rspamd,
        lookalike=lookalike,
        domain_age=domain_age,
        urlhaus=urlhaus,
        safebrowsing=safebrowsing,
        scoring=scoring,
        storage=storage,
        web=web,
    )
