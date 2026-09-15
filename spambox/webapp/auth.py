"""Autenticazione HTTP Basic per l'interfaccia di amministrazione."""
from __future__ import annotations

import hashlib
import hmac

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from spambox.config import WebConfig

security = HTTPBasic()


def make_verifier(web_config: WebConfig):
    def verify(credentials: HTTPBasicCredentials = Depends(security)) -> str:
        username_ok = hmac.compare_digest(credentials.username, web_config.username)
        supplied_hash = hashlib.sha256(credentials.password.encode()).hexdigest()
        password_ok = hmac.compare_digest(supplied_hash, web_config.password_sha256)
        if not (username_ok and password_ok):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenziali non valide",
                headers={"WWW-Authenticate": "Basic"},
            )
        return credentials.username

    return verify
