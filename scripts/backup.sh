#!/usr/bin/env bash
# Backup di SpamBox: dump sicuro del DB SQLite + config, staging in /tmp,
# invio verso storage cloud tramite rclone.
#
# Non fa un'immagine dell'intero sistema: l'installazione è riproducibile dal
# repository, quindi l'unico stato reale da salvare è il database (log delle
# analisi + domini protetti) e i file di configurazione.
#
# Configurazione: valorizzare config/backup.env (vedi backup.env.example).
set -euo pipefail

SPAMBOX_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ENV="${SPAMBOX_HOME}/config/backup.env"

if [[ -f "${BACKUP_ENV}" ]]; then
    # shellcheck disable=SC1090
    source "${BACKUP_ENV}"
fi

: "${SPAMBOX_CONFIG:=${SPAMBOX_HOME}/config/config.yaml}"
: "${RCLONE_REMOTE:?Impostare RCLONE_REMOTE in config/backup.env (es. gdrive:spambox-backups)}"
: "${BACKUP_RETENTION_DAYS:=30}"

DB_PATH="$(
    python3 - <<PYEOF
import sys
sys.path.insert(0, "${SPAMBOX_HOME}")
from spambox.config import load_config
print(load_config("${SPAMBOX_CONFIG}").storage.sqlite_path)
PYEOF
)"
# Path relativo -> assoluto rispetto alla working dir del progetto
case "${DB_PATH}" in
    /*) : ;;
    *) DB_PATH="${SPAMBOX_HOME}/${DB_PATH}" ;;
esac

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
TMP_DIR="$(mktemp -d "/tmp/spambox-backup.XXXXXX")"
ARCHIVE_NAME="spambox-backup-${TIMESTAMP}.tar.gz"
ARCHIVE_PATH="/tmp/${ARCHIVE_NAME}"

cleanup() {
    rm -rf "${TMP_DIR}" "${ARCHIVE_PATH}"
}
trap cleanup EXIT

echo "[backup] dump sicuro del database SQLite (${DB_PATH})..."
if [[ -f "${DB_PATH}" ]]; then
    sqlite3 "${DB_PATH}" ".backup '${TMP_DIR}/spambox.db'"
else
    echo "[backup] attenzione: database non trovato in ${DB_PATH}, salto il dump" >&2
fi

echo "[backup] copio i file di configurazione..."
mkdir -p "${TMP_DIR}/config"
[[ -f "${SPAMBOX_CONFIG}" ]] && cp "${SPAMBOX_CONFIG}" "${TMP_DIR}/config/"
[[ -f "${SPAMBOX_HOME}/config/spambox.env" ]] && cp "${SPAMBOX_HOME}/config/spambox.env" "${TMP_DIR}/config/"

echo "[backup] creo archivio ${ARCHIVE_PATH}..."
tar -czf "${ARCHIVE_PATH}" -C "${TMP_DIR}" .
chmod 600 "${ARCHIVE_PATH}"

echo "[backup] invio a ${RCLONE_REMOTE} via rclone..."
rclone copy "${ARCHIVE_PATH}" "${RCLONE_REMOTE}" --config "${RCLONE_CONFIG:-$HOME/.config/rclone/rclone.conf}"

if [[ "${BACKUP_RETENTION_DAYS}" -gt 0 ]]; then
    echo "[backup] pulizia backup remoti più vecchi di ${BACKUP_RETENTION_DAYS} giorni..."
    rclone delete "${RCLONE_REMOTE}" --min-age "${BACKUP_RETENTION_DAYS}d" \
        --config "${RCLONE_CONFIG:-$HOME/.config/rclone/rclone.conf}"
fi

echo "[backup] completato: ${ARCHIVE_NAME}"
