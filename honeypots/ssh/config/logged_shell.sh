#!/bin/bash
# Shell "espía": envuelve una bash real, registrando el inicio, cada
# comando y el fin de la sesión en un archivo que el agente vigila.
# Se instala como shell de login de los usuarios señuelo.
umask 0000
export HONEYPOT_WRAPPER_PID="$$"
SESSIONS_DIR="/var/log/honeypot/sessions"
mkdir -p "$SESSIONS_DIR"

# SSH_CONNECTION lo pone sshd automáticamente: "client_ip client_port server_ip server_port"
if [ -n "$SSH_CONNECTION" ]; then 
    CLIENT_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}') 
    CLIENT_PORT=$(echo "$SSH_CONNECTION" | awk '{print $2}')
else
    CLIENT_IP="local"
    CLIENT_PORT="$$"
fi

TS=$(date +%s)
SESSION_FILE="$SESSIONS_DIR/${USER}_${CLIENT_IP}_${CLIENT_PORT}_${TS}.log"

export HONEYPOT_SESSION_FILE="$SESSION_FILE"
export HONEYPOT_CLIENT_IP="$CLIENT_IP"
export HONEYPOT_CLIENT_PORT="$CLIENT_PORT"

printf 'START\t%s\t%s\t%s\t%s\n' \
    "$(date -Iseconds)" "$USER" "$CLIENT_IP" "$CLIENT_PORT" >> "$SESSION_FILE"

# Bash real e interactiva. No usamos "exec" para poder escribir el
# marcador de fin de sesión después de que el atacante haga exit/logout.
/bin/bash --rcfile /etc/honeypot/session_rc.sh -i
EXIT_CODE=$?

printf 'END\t%s\t%s\t%s\n' \
    "$(date -Iseconds)" "$CLIENT_IP" "$CLIENT_PORT" >> "$SESSION_FILE"

exit $EXIT_CODE