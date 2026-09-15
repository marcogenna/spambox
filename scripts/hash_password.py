#!/usr/bin/env python3
"""Utility per generare l'hash SHA-256 della password dell'interfaccia web.

Uso:
    python3 scripts/hash_password.py
    (verrà chiesta la password in modo interattivo, senza echo sul terminale)
"""
import getpass
import hashlib

if __name__ == "__main__":
    password = getpass.getpass("Password interfaccia web: ")
    confirm = getpass.getpass("Conferma password: ")
    if password != confirm:
        print("Le due password non coincidono.")
        raise SystemExit(1)
    print("\nSHA-256 da inserire in web.password_sha256 (o SPAMBOX_WEB_PASSWORD_SHA256):")
    print(hashlib.sha256(password.encode()).hexdigest())
