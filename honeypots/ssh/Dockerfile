FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-server \
        python3 \
        python3-pip \
        libpam-modules \
        iptables \
        wget \
        iputils-ping \
        iproute2 \
        curl && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd /var/log/honeypot /var/log/honeypot/sessions /etc/honeypot /app && \
    chmod 1777 /var/log/honeypot /var/log/honeypot/sessions

RUN ssh-keygen -A

# Usuarios débiles con shell espía.
# users.txt y create_users.sh se copian pero NO se ejecutan en build.
# El entrypoint los ejecuta en runtime, tras el put_archive de docker_utils
# que puede haber sobrescrito /tmp/users.txt con usuarios custom.
COPY ssh/config/users.txt /tmp/users.txt.default
COPY ssh/config/create_users.sh /tmp/create_users.sh
RUN chmod +x /tmp/create_users.sh

COPY ssh/config/sshd_config /etc/ssh/sshd_config
RUN rm -f /etc/motd /etc/update-motd.d/*
RUN rm -f /etc/motd /etc/update-motd.d/* /etc/legal
COPY ssh/config/motd.sh /etc/update-motd.d/00-honeypot
RUN chmod +x /etc/update-motd.d/00-honeypot

# Shell espía
COPY ssh/config/logged_shell.sh /usr/local/bin/logged-shell
RUN chmod +x /usr/local/bin/logged-shell
COPY ssh/config/session_rc.sh /etc/honeypot/session_rc.sh

# Captura de contraseña vía PAM
COPY ssh/config/capture_auth.sh /usr/local/bin/capture_auth.sh
RUN chmod +x /usr/local/bin/capture_auth.sh
RUN sed -i '1i auth optional pam_exec.so quiet expose_authtok /usr/local/bin/capture_auth.sh' /etc/pam.d/sshd

# Agente Python
WORKDIR /app
COPY ssh/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY common/ ./common/
COPY ssh/agent.py .
COPY ssh/monitor/ ./monitor/

COPY ssh/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]

RUN chown -R root:root /app && \
    chmod -R 700 /app