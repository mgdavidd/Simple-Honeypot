#!/bin/bash
set -e

USERS_FILE="/tmp/users.txt"
SHELL_PATH="/usr/local/bin/logged-shell"

while IFS=: read -r username password; do
    [ -z "$username" ] && continue

    if [ "$username" = "root" ]; then
        echo "root:$password" | chpasswd
        usermod -s "$SHELL_PATH" root
    else
        useradd -m -s "$SHELL_PATH" "$username"
        echo "$username:$password" | chpasswd
    fi

    echo "[+] Usuario creado: $username (shell: $SHELL_PATH)"
done < "$USERS_FILE"