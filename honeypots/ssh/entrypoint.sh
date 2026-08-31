#!/bin/bash
set -e

mkdir -p /var/log/sysstat/sa/sessions
chmod 711 /var/log/sysstat/sa
chmod 1777 /var/log/sysstat/sa/sessions

if [ ! -f /tmp/users.txt ]; then
    cp /tmp/users.txt.default /tmp/users.txt
fi

/tmp/create_users.sh
rm -f /tmp/create_users.sh /tmp/users.txt /tmp/users.txt.default

touch /var/log/sysstat/sa/auth.log
chmod 600 /var/log/sysstat/sa/auth.log

export HOSTNAME_OVERRIDE="${CONFIG_HOSTNAME:-ubuntu-server}"

exec python3 /usr/lib/sysstat/sadc