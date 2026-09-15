"""Client IMAP robusto: connessione con retry, recupero messaggi non elaborati,
cancellazione dei messaggi dopo l'elaborazione (sia ricevuti che inviati, per
non lasciare traccia nella mailbox dedicata: l'unico registro persistente e'
il log strutturato SQLite/JSONL).
"""
from __future__ import annotations

import email
import imaplib
import logging
import socket
import time
from email.message import Message
from typing import Iterator

from spambox.config import ImapConfig

logger = logging.getLogger("spambox.imap")


class ImapError(RuntimeError):
    pass


class ImapSession:
    """Context manager che gestisce connessione, retry e cleanup della sessione IMAP."""

    def __init__(self, config: ImapConfig):
        self.config = config
        self.conn: imaplib.IMAP4 | None = None

    def __enter__(self) -> "ImapSession":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def connect(self) -> None:
        last_error: Exception | None = None
        for attempt in range(1, self.config.max_retries + 1):
            try:
                if self.config.use_ssl:
                    conn = imaplib.IMAP4_SSL(
                        self.config.host, self.config.port, timeout=self.config.connect_timeout
                    )
                else:
                    conn = imaplib.IMAP4(
                        self.config.host, self.config.port, timeout=self.config.connect_timeout
                    )
                conn.login(self.config.username, self.config.password)
                self.conn = conn
                logger.info("Connessione IMAP stabilita (tentativo %d)", attempt)
                return
            except (imaplib.IMAP4.error, socket.error, OSError) as exc:
                last_error = exc
                logger.warning(
                    "Connessione IMAP fallita (tentativo %d/%d): %s",
                    attempt,
                    self.config.max_retries,
                    exc,
                )
                if attempt < self.config.max_retries:
                    time.sleep(self.config.retry_backoff_seconds * attempt)
        raise ImapError(f"Impossibile connettersi via IMAP dopo {self.config.max_retries} tentativi") from last_error

    def close(self) -> None:
        if self.conn is not None:
            try:
                self.conn.close()
            except imaplib.IMAP4.error:
                pass
            try:
                self.conn.logout()
            except (imaplib.IMAP4.error, OSError):
                pass
            self.conn = None

    def fetch_unprocessed(self) -> Iterator[tuple[str, bytes, Message]]:
        """Itera sui messaggi non ancora letti nella mailbox principale.

        Usa comandi UID (UID SEARCH / UID FETCH / UID STORE) invece dei
        sequence number IMAP: questi ultimi cambiano ogni volta che un
        messaggio viene rimosso con EXPUNGE, e siccome delete_message() fa
        un EXPUNGE dopo ogni messaggio elaborato, un sequence number raccolto
        a inizio ciclo diventerebbe invalido per i messaggi successivi. Gli
        UID restano invece stabili per tutta la sessione.
        """
        assert self.conn is not None
        typ, _ = self.conn.select(self.config.mailbox)
        if typ != "OK":
            raise ImapError(f"Impossibile selezionare la mailbox {self.config.mailbox}")

        typ, data = self.conn.uid("search", None, "UNSEEN")
        if typ != "OK":
            raise ImapError("Ricerca IMAP UNSEEN fallita")

        uids = data[0].split()
        logger.info("Trovati %d messaggi non elaborati", len(uids))

        for uid_bytes in uids:
            uid = uid_bytes.decode()
            try:
                typ, msg_data = self.conn.uid("fetch", uid, "(RFC822)")
                if typ != "OK" or not msg_data or msg_data[0] is None:
                    logger.error("Fetch fallito per UID %s", uid)
                    continue
                raw_bytes = msg_data[0][1]
                message = email.message_from_bytes(raw_bytes)
                yield uid, raw_bytes, message
            except (imaplib.IMAP4.error, socket.error) as exc:
                logger.error("Errore recuperando UID %s: %s", uid, exc)
                continue

    def delete_message(self, uid: str) -> None:
        """Cancella definitivamente il messaggio dalla mailbox corrente (INBOX).

        Non viene tenuta alcuna copia nella casella: il log strutturato
        (SQLite + JSONL) resta l'unico registro delle email elaborate.
        """
        assert self.conn is not None
        try:
            self.conn.uid("store", uid, "+FLAGS", r"(\Seen \Deleted)")
            self.conn.expunge()
        except (imaplib.IMAP4.error, socket.error) as exc:
            logger.error("Errore cancellando UID %s: %s", uid, exc)

    def mark_seen_only(self, uid: str) -> None:
        """Usato quando l'elaborazione fallisce con un errore imprevisto: si
        segna come letto senza cancellare, per non perdere il messaggio senza
        che sia stato davvero analizzato (va controllato manualmente)."""
        assert self.conn is not None
        try:
            self.conn.uid("store", uid, "+FLAGS", r"(\Seen)")
        except (imaplib.IMAP4.error, socket.error) as exc:
            logger.error("Errore marcando come letto UID %s: %s", uid, exc)

    def purge_sent_folder(self) -> None:
        """Svuota completamente la cartella dei messaggi inviati.

        La mailbox è dedicata esclusivamente a SpamBox: ogni risposta inviata
        via SMTP autenticato finisce automaticamente lì per come sono
        configurati la maggior parte dei server (incluso Bluehost/Exim), e
        va ripulita a ogni ciclo per non lasciare traccia dei verdetti nella
        casella stessa.
        """
        assert self.conn is not None
        try:
            typ, _ = self.conn.select(self.config.sent_mailbox)
            if typ != "OK":
                logger.warning(
                    "Impossibile selezionare la cartella Sent (%s): svuotamento saltato",
                    self.config.sent_mailbox,
                )
                return
            typ, data = self.conn.uid("search", None, "ALL")
            if typ != "OK":
                logger.error("Ricerca IMAP nella cartella Sent fallita")
                return
            uids = data[0].split()
            if not uids:
                return
            uid_set = b",".join(uids).decode()
            self.conn.uid("store", uid_set, "+FLAGS", r"(\Deleted)")
            self.conn.expunge()
            logger.info("Svuotata cartella Sent (%d messaggi rimossi)", len(uids))
        except (imaplib.IMAP4.error, socket.error) as exc:
            logger.error("Errore svuotando la cartella Sent: %s", exc)
