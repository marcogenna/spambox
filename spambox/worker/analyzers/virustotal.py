"""Integrazione con VirusTotal API v3: lookup URL e hash allegati.

Design deliberato per l'MVP:
- Per gli URL si esegue una GET sul report esistente (id = base64url(url) senza
  padding). Non si effettua l'upload/submit dell'URL per non consumare quota e
  per non introdurre attese di scansione: se VT non ha ancora un report per
  quell'URL viene segnalato come "sconosciuto" (non e' un errore).
- Per gli allegati si interroga SOLO l'hash SHA256 (nessun upload del file):
  compatibile con l'obbligo di non far girare codice non fidato e di rispettare
  la quota gratuita.
- Rate limiting: token bucket semplice basato su requests_per_minute, con
  gestione esplicita di 429 (quota superata) e di errori di rete/timeout: in
  nessun caso una risposta anomala di VT deve far fallire l'intera analisi.
"""
from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass
from typing import Any

import requests

from spambox.config import VirusTotalConfig

logger = logging.getLogger("spambox.virustotal")


class _RateLimiter:
    def __init__(self, requests_per_minute: int):
        self.min_interval = 60.0 / max(requests_per_minute, 1)
        self._last_call = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_call = time.monotonic()


@dataclass
class VtLookupResult:
    identifier: str
    kind: str  # "url" o "file"
    status: str  # "malicious", "suspicious", "clean", "unknown", "error", "quota_exceeded"
    malicious_count: int = 0
    suspicious_count: int = 0
    total_engines: int = 0
    categories: dict[str, str] | None = None
    detail: str = ""


class VirusTotalClient:
    def __init__(self, config: VirusTotalConfig):
        self.config = config
        self._limiter = _RateLimiter(config.requests_per_minute)

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self.config.api_key}

    def _get(self, path: str) -> tuple[int, dict[str, Any]]:
        self._limiter.wait()
        url = f"{self.config.base_url.rstrip('/')}{path}"
        resp = requests.get(
            url, headers=self._headers(), timeout=self.config.request_timeout_seconds
        )
        try:
            body = resp.json()
        except ValueError:
            body = {}
        return resp.status_code, body

    def lookup_url(self, target_url: str) -> VtLookupResult:
        try:
            url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
            status_code, body = self._get(f"/urls/{url_id}")
            return self._parse_response(target_url, "url", status_code, body)
        except requests.exceptions.RequestException as exc:
            logger.warning("Errore di rete interrogando VT per URL %s: %s", target_url, exc)
            return VtLookupResult(target_url, "url", "error", detail=str(exc))

    def lookup_file_hash(self, sha256: str) -> VtLookupResult:
        try:
            status_code, body = self._get(f"/files/{sha256}")
            return self._parse_response(sha256, "file", status_code, body)
        except requests.exceptions.RequestException as exc:
            logger.warning("Errore di rete interrogando VT per hash %s: %s", sha256, exc)
            return VtLookupResult(sha256, "file", "error", detail=str(exc))

    def _parse_response(
        self, identifier: str, kind: str, status_code: int, body: dict[str, Any]
    ) -> VtLookupResult:
        if status_code == 404:
            return VtLookupResult(identifier, kind, "unknown", detail="non presente su VirusTotal")
        if status_code == 429:
            logger.warning("Quota VirusTotal superata")
            return VtLookupResult(identifier, kind, "quota_exceeded", detail="rate limit VirusTotal superato")
        if status_code == 401:
            return VtLookupResult(identifier, kind, "error", detail="API key VirusTotal non valida")
        if status_code != 200:
            return VtLookupResult(identifier, kind, "error", detail=f"status HTTP {status_code}")

        try:
            attributes = body["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = sum(stats.values()) if stats else 0
            categories = attributes.get("categories") or None

            if malicious > 0:
                status = "malicious"
            elif suspicious > 0:
                status = "suspicious"
            else:
                status = "clean"

            return VtLookupResult(
                identifier=identifier,
                kind=kind,
                status=status,
                malicious_count=malicious,
                suspicious_count=suspicious,
                total_engines=total,
                categories=categories,
            )
        except (KeyError, TypeError) as exc:
            logger.warning("Risposta VirusTotal inattesa per %s: %s", identifier, exc)
            return VtLookupResult(identifier, kind, "error", detail="risposta VirusTotal non interpretabile")


def analyze_urls_and_attachments(
    urls: list[str], attachment_hashes: list[str], config: VirusTotalConfig
) -> dict[str, Any]:
    """Analizza URL e hash allegati rispettando i limiti configurati.

    Restituisce un dizionario riassuntivo pronto per essere loggato e usato
    nello scoring, senza mai sollevare eccezioni verso il chiamante.
    """
    if not config.enabled:
        return {"available": False, "reason": "disabilitato in configurazione", "urls": [], "files": []}
    if not config.api_key or config.api_key.startswith("PLACEHOLDER"):
        logger.warning("API key VirusTotal non configurata: analisi VT saltata")
        return {"available": False, "reason": "API key non configurata", "urls": [], "files": []}

    client = VirusTotalClient(config)
    url_results = []
    file_results = []
    had_quota_error = False

    for u in urls[: config.max_urls_per_message]:
        result = client.lookup_url(u)
        if result.status == "quota_exceeded":
            had_quota_error = True
        url_results.append(result.__dict__)

    for h in attachment_hashes[: config.max_attachments_per_message]:
        result = client.lookup_file_hash(h)
        if result.status == "quota_exceeded":
            had_quota_error = True
        file_results.append(result.__dict__)

    return {
        "available": True,
        "quota_exceeded": had_quota_error,
        "urls": url_results,
        "files": file_results,
    }
