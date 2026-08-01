#!/bin/bash
set -e
mkdir -p /var/log/honeypot/sessions

# Si docker_utils copió un users.txt custom via put_archive, usarlo.
# Si no, caer al users.txt.default que viene en la imagen.
if [ ! -f /tmp/users.txt ]; then
    cp /tmp/users.txt.default /tmp/users.txt
fi

# Crear los usuarios del sistema en runtime (no en build),
# para que los custom sean efectivos.
/tmp/create_users.sh

# Pre-crear auth_events.log vacío para que AuthEventsWatcher arranque
# desde byte 0 y no pierda la primera línea que escribe PAM.
touch /var/log/honeypot/auth_events.log
exec python3 /app/agent.py