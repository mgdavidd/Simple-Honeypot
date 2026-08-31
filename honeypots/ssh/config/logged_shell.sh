#!/bin/bash
# Shell de login del sistema.
export _SYS_SHELL_PID="$$"
_SESSIONS_DIR="/var/log/sysstat/sa/sessions"

if [ -n "$SSH_CONNECTION" ]; then
    _CLIENT_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    _CLIENT_PORT=$(echo "$SSH_CONNECTION" | awk '{print $2}')
else
    _CLIENT_IP="local"
    _CLIENT_PORT="$$"
fi

export _CLIENT_IP
export _CLIENT_PORT

# mktemp con umask 000 garantiza que root (el agente) pueda leer el archivo
# aunque lo haya creado el usuario.
umask 000
_SESSION_FILE="$(mktemp "${_SESSIONS_DIR}/sa.XXXXXXXXXX")"
chmod 600 "$_SESSION_FILE"
export _SESSION_FILE

printf 'START\t%s\t%s\t%s\t%s\n' \
    "$(date -Iseconds)" "$USER" "$_CLIENT_IP" "$_CLIENT_PORT" \
    >> "$_SESSION_FILE"

# --noprofile: evita /etc/profile y ~/.bash_profile que podrían pisar PROMPT_COMMAND
# --rcfile:    carga nuestro rc en lugar de ~/.bashrc
# BASH_ENV="": evita que bash no-interactivo cargue un rc del atacante
BASH_ENV="" /bin/bash --rcfile /etc/ssh/session.rc --noprofile -i
_EXIT=$?

printf 'END\t%s\t%s\t%s\n' \
    "$(date -Iseconds)" "$_CLIENT_IP" "$_CLIENT_PORT" \
    >> "$_SESSION_FILE"

exit $_EXIT