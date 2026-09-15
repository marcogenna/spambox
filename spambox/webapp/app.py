"""Interfaccia web di amministrazione SpamBox (FastAPI).

Gestisce:
- CRUD dei domini legittimi protetti (usati dal worker per il rilevamento lookalike)
- Consultazione dei log di analisi, con filtri per data/verdetto/mittente

Condivide lo stesso database SQLite del worker.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from spambox import db
from spambox.config import load_config
from spambox.webapp.auth import make_verifier

config = load_config()
db.init_db(config.storage.sqlite_path)

app = FastAPI(title="SpamBox Admin")
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
templates_dir = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

verify_user = make_verifier(config.web)


@app.get("/")
def index(request: Request, user: str = Depends(verify_user)):
    return RedirectResponse(url="/logs")


@app.get("/domains")
def domains_page(request: Request, user: str = Depends(verify_user)):
    domains = db.list_domains(config.storage.sqlite_path)
    return templates.TemplateResponse(
        request, "domains.html", {"domains": domains, "user": user}
    )


@app.post("/domains/add")
def domains_add(
    request: Request,
    domain: str = Form(...),
    note: str = Form(""),
    user: str = Depends(verify_user),
):
    if domain.strip():
        db.add_domain(config.storage.sqlite_path, domain, note)
    return RedirectResponse(url="/domains", status_code=303)


@app.post("/domains/{domain_id}/update")
def domains_update(
    domain_id: int,
    domain: str = Form(...),
    note: str = Form(""),
    user: str = Depends(verify_user),
):
    db.update_domain(config.storage.sqlite_path, domain_id, domain, note)
    return RedirectResponse(url="/domains", status_code=303)


@app.post("/domains/{domain_id}/delete")
def domains_delete(domain_id: int, user: str = Depends(verify_user)):
    db.delete_domain(config.storage.sqlite_path, domain_id)
    return RedirectResponse(url="/domains", status_code=303)


@app.get("/allowed-domains")
def allowed_domains_page(request: Request, user: str = Depends(verify_user)):
    domains = db.list_allowed_forwarder_domains(config.storage.sqlite_path)
    return templates.TemplateResponse(
        request, "allowed_domains.html", {"domains": domains, "user": user}
    )


@app.post("/allowed-domains/add")
def allowed_domains_add(
    request: Request,
    domain: str = Form(...),
    note: str = Form(""),
    user: str = Depends(verify_user),
):
    if domain.strip():
        db.add_allowed_forwarder_domain(config.storage.sqlite_path, domain, note)
    return RedirectResponse(url="/allowed-domains", status_code=303)


@app.post("/allowed-domains/{domain_id}/update")
def allowed_domains_update(
    domain_id: int,
    domain: str = Form(...),
    note: str = Form(""),
    user: str = Depends(verify_user),
):
    db.update_allowed_forwarder_domain(config.storage.sqlite_path, domain_id, domain, note)
    return RedirectResponse(url="/allowed-domains", status_code=303)


@app.post("/allowed-domains/{domain_id}/delete")
def allowed_domains_delete(domain_id: int, user: str = Depends(verify_user)):
    db.delete_allowed_forwarder_domain(config.storage.sqlite_path, domain_id)
    return RedirectResponse(url="/allowed-domains", status_code=303)


@app.get("/logs")
def logs_page(
    request: Request,
    date_from: str = "",
    date_to: str = "",
    verdict: str = "",
    sender: str = "",
    user: str = Depends(verify_user),
):
    rows = db.query_logs(
        config.storage.sqlite_path,
        date_from=date_from or None,
        date_to=date_to or None,
        verdict=verdict or None,
        sender=sender or None,
    )
    logs = []
    for row in rows:
        entry = dict(row)
        entry["reasons"] = json.loads(entry.get("reasons_json") or "[]")
        entry["lookalike"] = json.loads(entry.get("lookalike_json") or "{}")
        entry["virustotal"] = json.loads(entry.get("virustotal_json") or "{}")
        entry["urlhaus"] = json.loads(entry.get("urlhaus_json") or "{}")
        entry["safebrowsing"] = json.loads(entry.get("safebrowsing_json") or "{}")
        entry["domain_age"] = json.loads(entry.get("domain_age_json") or "{}")
        entry["brand_impersonation"] = json.loads(entry.get("brand_impersonation_json") or "{}")
        logs.append(entry)

    return templates.TemplateResponse(
        request,
        "logs.html",
        {
            "logs": logs,
            "user": user,
            "filters": {
                "date_from": date_from,
                "date_to": date_to,
                "verdict": verdict,
                "sender": sender,
            },
        },
    )
