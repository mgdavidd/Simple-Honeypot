#!/bin/bash
# Solo ejecutar para el servicio sshd — evita ejecuciones duplicadas
# por otros módulos PAM que también llaman a pam_exec
[ "$PAM_SERVICE" != "sshd" ] && exit 0

PASSWORD=$(cat)
LOGFILE="/var/log/honeypot/auth_events.log"
mkdir -p "$(dirname "$LOGFILE")"

# Limpiar contraseña: eliminar tabs, newlines y caracteres de control
# para no romper el formato TSV ni capturar basura de mensajes PAM
CLEAN_PASSWORD=$(printf '%s' "$PASSWORD" | tr -d '\t\n\r\b' | tr -cd '[:print:]')

printf 'AUTH\t%s\t%s\t%s\t%s\n' \
    "$(date -Iseconds)" \
    "${PAM_USER:-unknown}" \
    "${PAM_RHOST:-unknown}" \
    "$CLEAN_PASSWORD" \
    >> "$LOGFILE"