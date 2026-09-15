"""Interfaccia web di amministrazione SpamBox (FastAPI).

Gestisce:
- CRUD dei domini legittimi protetti (usati dal worker per il rilevamento lookalike)
- Consultazione dei log di analisi, con filtri per data/verdetto/mittente
- Campagne di phishing simulato verso i dipendenti (situation awareness)

Condivide lo stesso database SQLite del worker.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from spambox import db
from spambox.campaigns.mailer import generate_token, send_campaign_email
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
logger_campaigns = logging.getLogger("spambox.webapp.campaigns")


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


# ---------------------------------------------------------------------------
# Campagne di phishing simulato (situation awareness)
# ---------------------------------------------------------------------------

def _parse_targets_input(raw_text: str) -> list[tuple[str, str, str]]:
    """Una riga per destinatario: 'email' oppure 'email,team'. Righe vuote o
    senza '@' vengono ignorate. Restituisce (email, team, token)."""
    targets = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or "@" not in line:
            continue
        parts = [p.strip() for p in line.split(",", 1)]
        email = parts[0].lower()
        team = parts[1] if len(parts) > 1 else ""
        targets.append((email, team, generate_token()))
    return targets


@app.get("/campaigns")
def campaigns_page(request: Request, user: str = Depends(verify_user)):
    campaigns = [dict(c) for c in db.list_campaigns(config.storage.sqlite_path)]
    for c in campaigns:
        c["stats"] = db.campaign_stats(config.storage.sqlite_path, c["id"])
    return templates.TemplateResponse(
        request,
        "campaigns.html",
        {
            "campaigns": campaigns,
            "user": user,
            "campaigns_enabled": config.campaigns.enabled,
            "public_base_url": config.campaigns.public_base_url,
        },
    )


@app.get("/campaigns/new")
def campaign_new_page(request: Request, user: str = Depends(verify_user)):
    return templates.TemplateResponse(request, "campaign_new.html", {"user": user})


@app.post("/campaigns/add")
def campaign_add(
    request: Request,
    name: str = Form(...),
    subject: str = Form(...),
    body_html: str = Form(...),
    sender_display_name: str = Form(...),
    landing_page_html: str = Form(...),
    targets_text: str = Form(""),
    user: str = Depends(verify_user),
):
    campaign_id = db.create_campaign(
        config.storage.sqlite_path, name, subject, body_html, sender_display_name, landing_page_html
    )
    targets = _parse_targets_input(targets_text)
    if targets:
        db.create_campaign_targets_bulk(config.storage.sqlite_path, campaign_id, targets)
    return RedirectResponse(url=f"/campaigns/{campaign_id}", status_code=303)


@app.get("/campaigns/{campaign_id}")
def campaign_detail_page(request: Request, campaign_id: int, user: str = Depends(verify_user)):
    campaign = db.get_campaign(config.storage.sqlite_path, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campagna non trovata")
    targets = db.list_campaign_targets(config.storage.sqlite_path, campaign_id)
    stats = db.campaign_stats(config.storage.sqlite_path, campaign_id)
    return templates.TemplateResponse(
        request,
        "campaign_detail.html",
        {
            "campaign": dict(campaign),
            "targets": targets,
            "stats": stats,
            "user": user,
            "campaigns_enabled": config.campaigns.enabled,
            "public_base_url": config.campaigns.public_base_url,
        },
    )


def _launch_campaign_background(campaign_id: int) -> None:
    campaign = db.get_campaign(config.storage.sqlite_path, campaign_id)
    if campaign is None:
        return
    base_url = config.campaigns.public_base_url.rstrip("/")
    for target in db.list_campaign_targets(config.storage.sqlite_path, campaign_id):
        if target["sent_at"]:
            continue
        link = f"{base_url}/sim/click/{target['token']}"
        try:
            send_campaign_email(
                config.smtp,
                target["email"],
                campaign["subject"],
                campaign["body_html"],
                campaign["sender_display_name"],
                link,
            )
            db.mark_target_sent(config.storage.sqlite_path, target["id"])
        except Exception:  # noqa: BLE001 - un fallimento di invio non deve fermare gli altri
            logger_campaigns.exception("Invio campagna fallito per %s", target["email"])
    db.set_campaign_status(config.storage.sqlite_path, campaign_id, "completed", launched=True)


@app.post("/campaigns/{campaign_id}/launch")
def campaign_launch(
    campaign_id: int, background_tasks: BackgroundTasks, user: str = Depends(verify_user)
):
    if not config.campaigns.enabled or not config.campaigns.public_base_url:
        raise HTTPException(
            status_code=400,
            detail="Le campagne non sono abilitate o manca 'campaigns.public_base_url' in config.yaml",
        )
    db.set_campaign_status(config.storage.sqlite_path, campaign_id, "sending")
    background_tasks.add_task(_launch_campaign_background, campaign_id)
    return RedirectResponse(url=f"/campaigns/{campaign_id}", status_code=303)


@app.get("/sim/click/{token}", response_class=HTMLResponse)
def sim_click(token: str):
    """Rotta PUBBLICA (nessuna autenticazione): i dipendenti la raggiungono
    cliccando il link dell'email di test, da qualunque rete."""
    target = db.mark_target_clicked(config.storage.sqlite_path, token)
    if target is None:
        raise HTTPException(status_code=404, detail="Link non valido o scaduto")
    campaign = db.get_campaign(config.storage.sqlite_path, target["campaign_id"])
    landing_html = campaign["landing_page_html"] if campaign else "<p>Questo era un test di sicurezza.</p>"
    return HTMLResponse(content=landing_html)
