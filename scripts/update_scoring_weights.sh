#!/usr/bin/env bash
# Aggiorna i pesi della sezione "scoring:" in config/config.yaml con sed,
# senza dover editare il file a mano. Fa un backup con timestamp prima di
# modificare, ed e' idempotente: rilanciarlo piu' volte non crea duplicati.
#
# Uso (sulla RPi):
#   ./scripts/update_scoring_weights.sh
# oppure specificando un altro percorso:
#   ./scripts/update_scoring_weights.sh /percorso/a/config.yaml
set -euo pipefail

CONFIG_FILE="${1:-/opt/spambox/config/config.yaml}"

if [[ ! -f "${CONFIG_FILE}" ]]; then
    echo "File non trovato: ${CONFIG_FILE}" >&2
    exit 1
fi

BACKUP_FILE="${CONFIG_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
cp "${CONFIG_FILE}" "${BACKUP_FILE}"
echo "Backup creato: ${BACKUP_FILE}"

# Aggiorna i pesi esistenti (sostituisce solo il valore, mantenendo il resto
# della riga/commenti). -E per le regex estese, compatibile sia con GNU sed
# (Linux/DietPi) sia con BSD sed (macOS) grazie a "-i" seguito da stringa vuota
# gestita separatamente sotto.
# Coppie chiave=valore invece di un array associativo (declare -A), per
# restare compatibili anche con bash 3.2 (es. quello di default su macOS).
WEIGHTS=(
    "weight_rspamd=0.18"
    "weight_virustotal=0.18"
    "weight_lookalike=0.11"
    "weight_auth_failure=0.05"
    "weight_domain_age=0.07"
    "weight_urlhaus=0.10"
    "weight_safebrowsing=0.12"
    "weight_brand_impersonation=0.09"
    "weight_reply_to_mismatch=0.09"
)

# Rileva se sed e' GNU (Linux) o BSD (macOS) per usare la sintassi -i corretta
if sed --version >/dev/null 2>&1; then
    SED_INPLACE=(-i)          # GNU sed: -i senza argomento
else
    SED_INPLACE=(-i '')       # BSD sed: -i richiede un argomento (stringa vuota = nessun backup extra)
fi

for pair in "${WEIGHTS[@]}"; do
    key="${pair%%=*}"
    value="${pair#*=}"
    if grep -qE "^[[:space:]]*${key}[[:space:]]*:" "${CONFIG_FILE}"; then
        # Chiave gia' presente: aggiorna solo il valore
        sed "${SED_INPLACE[@]}" -E "s/^([[:space:]]*${key}[[:space:]]*:[[:space:]]*)[0-9.]+/\1${value}/" "${CONFIG_FILE}"
        echo "Aggiornato: ${key} = ${value}"
    else
        # Chiave assente: la inserisce subito prima di "threshold_sospetta:"
        sed "${SED_INPLACE[@]}" -E "s/^([[:space:]]*)(threshold_sospetta[[:space:]]*:.*)/\1${key}: ${value}\n\1\2/" "${CONFIG_FILE}"
        echo "Aggiunto:   ${key} = ${value}"
    fi
done

echo ""
echo "=== Sezione scoring risultante ==="
sed -n '/^scoring:/,/^[a-z_]*:/p' "${CONFIG_FILE}" | sed '$d'
