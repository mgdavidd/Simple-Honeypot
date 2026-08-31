#!/bin/bash
set -euo pipefail

USERS_FILE="${USERS_FILE:-/tmp/users.txt}"
SHELL_PATH="${SHELL_PATH:-/usr/local/bin/sysinfo}"

if [ ! -f "$USERS_FILE" ]; then
    exit 0
fi

while IFS=: read -r username password || [ -n "${username:-}" ]; do
    username="${username%$'\r'}"
    password="${password:-}"
    password="${password%$'\r'}"

    [ -z "${username:-}" ] && continue

    if id -u "$username" >/dev/null 2>&1; then
        :
    else
        if [ "$username" = "root" ]; then
            usermod -s "$SHELL_PATH" root
        else
            useradd -m -s "$SHELL_PATH" "$username"
        fi
    fi

    if [ "$username" = "root" ]; then
        echo "root:$password" | chpasswd
        usermod -s "$SHELL_PATH" root
    else
        echo "$username:$password" | chpasswd
    fi

done < "$USERS_FILE"