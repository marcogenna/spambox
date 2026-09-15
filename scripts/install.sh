#!/usr/bin/env bash
# Installazione automatica di SpamBox su Debian/DietPi/Raspberry Pi OS.
# Esegue tutti i passaggi manuali descritti nel README: pacchetti di sistema,
# utente dedicato, ambiente Python, file di configurazione, unit systemd.
#
# Uso (da root, sulla macchina di destinazione):
#   curl -fsSL https://raw.githubusercontent.com/<org>/spambox/main/scripts/install.sh | bash
# oppure, dopo aver clonato il repo:
#   sudo ./scripts/install.sh
#
# È SICURO rilanciarlo più volte (idempotente dove ragionevole): non
# sovrascrive config.yaml/spambox.env se già esistenti, non duplica il
# lavoro già fatto.
set -euo pipefail

INSTALL_DIR="${SPAMBOX_INSTALL_DIR:-/opt/spambox}"
SERVICE_USER="${SPAMBOX_USER:-spambox}"
REPO_URL="${SPAMBOX_REPO_URL:-}"

log() { echo -e "\n\033[1;32m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m[ATTENZIONE]\033[0m $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    echo "Questo script va eseguito come root (o con sudo)." >&2
    exit 1
fi

log "1/7 - Pacchetti di sistema"
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3-venv python3-pip sqlite3 rclone rspamd git ca-certificates >/dev/null
log "Pacchetti installati."

log "2/7 - Utente di sistema dedicato"
if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd --system --home "${INSTALL_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
    log "Utente '${SERVICE_USER}' creato."
else
    log "Utente '${SERVICE_USER}' già esistente, salto."
fi
mkdir -p "${INSTALL_DIR}"

log "3/7 - Codice sorgente"
if [[ -f "${INSTALL_DIR}/requirements.txt" ]]; then
    log "Codice già presente in ${INSTALL_DIR}, salto la copia (aggiorna a mano con rsync/git pull se serve)."
elif [[ -n "${REPO_URL}" ]]; then
    git clone --depth 1 "${REPO_URL}" "${INSTALL_DIR}"
elif [[ -f "$(dirname "$0")/../requirements.txt" ]]; then
    # Lo script è eseguito da dentro un checkout locale del repo: copia da lì
    SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
    rsync -a --exclude venv --exclude data --exclude logs --exclude '.git' \
        "${SOURCE_DIR}/" "${INSTALL_DIR}/"
else
    echo "Impossibile trovare il codice sorgente: imposta SPAMBOX_REPO_URL oppure" >&2
    echo "esegui questo script da dentro un checkout del repository." >&2
    exit 1
fi
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"

log "4/7 - Ambiente Python"
sudo -u "${SERVICE_USER}" python3 -m venv "${INSTALL_DIR}/venv"
sudo -u "${SERVICE_USER}" "${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade pip
sudo -u "${SERVICE_USER}" "${INSTALL_DIR}/venv/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt"
log "Ambiente virtuale creato in ${INSTALL_DIR}/venv."

log "5/7 - File di configurazione"
if [[ ! -f "${INSTALL_DIR}/config/config.yaml" ]]; then
    sudo -u "${SERVICE_USER}" cp "${INSTALL_DIR}/config/config.example.yaml" "${INSTALL_DIR}/config/config.yaml"
    log "Creato config/config.yaml dal template — VA COMPILATO A MANO prima di avviare i servizi."
else
    log "config/config.yaml già esistente, non toccato."
fi
if [[ ! -f "${INSTALL_DIR}/config/spambox.env" ]]; then
    sudo -u "${SERVICE_USER}" cp "${INSTALL_DIR}/config/spambox.env.example" "${INSTALL_DIR}/config/spambox.env"
    chmod 600 "${INSTALL_DIR}/config/spambox.env"
    log "Creato config/spambox.env dal template — VA COMPILATO A MANO con le credenziali reali."
else
    log "config/spambox.env già esistente, non toccato."
fi

log "6/7 - Database e directory dati"
sudo -u "${SERVICE_USER}" mkdir -p "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs"
sudo -u "${SERVICE_USER}" env SPAMBOX_CONFIG="${INSTALL_DIR}/config/config.yaml" \
    "${INSTALL_DIR}/venv/bin/python" "${INSTALL_DIR}/scripts/init_db.py" || \
    warn "Inizializzazione DB saltata (probabilmente config.yaml non ancora compilato: rilancia dopo averlo compilato)."

log "7/7 - Unit systemd"
cp "${INSTALL_DIR}/systemd/spambox-worker.service" \
   "${INSTALL_DIR}/systemd/spambox-worker.timer" \
   "${INSTALL_DIR}/systemd/spambox-web.service" \
   /etc/systemd/system/
if [[ -f "${INSTALL_DIR}/systemd/spambox-logrotate.conf" ]]; then
    cp "${INSTALL_DIR}/systemd/spambox-logrotate.conf" /etc/logrotate.d/spambox
fi
systemctl daemon-reload

cat <<EOF

==================================================================
Installazione base completata in ${INSTALL_DIR}.

PRIMA DI ATTIVARE I SERVIZI, completa manualmente:
  1. nano ${INSTALL_DIR}/config/config.yaml       (host IMAP/SMTP, soglie, ecc.)
  2. nano ${INSTALL_DIR}/config/spambox.env       (password, API key)
  3. ${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/scripts/hash_password.py
     (poi incolla l'hash in SPAMBOX_WEB_PASSWORD_SHA256 dentro spambox.env)

Poi attiva i servizi:
  systemctl enable --now spambox-worker.timer
  systemctl enable --now spambox-web.service

Verifica che tutto funzioni con:
  sudo -u ${SERVICE_USER} bash -c 'set -a; source ${INSTALL_DIR}/config/spambox.env; set +a; ${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/scripts/diagnose.py'

Vedi il README.md per la configurazione completa (whitelist mittenti,
domini protetti, backup, ecc.).
==================================================================
EOF
