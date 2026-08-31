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

RUN mkdir -p /var/run/sshd \
             /var/log/sysstat/sa \
             /var/log/sysstat/sa/sessions && \
    chmod 711 /var/log/sysstat/sa && \
    chmod 1777 /var/log/sysstat/sa/sessions

RUN ssh-keygen -A

COPY ssh/config/users.txt /tmp/users.txt.default
COPY ssh/config/create_users.sh /tmp/create_users.sh
RUN chmod +x /tmp/create_users.sh

COPY ssh/config/sshd_config /etc/ssh/sshd_config
RUN rm -f /etc/motd /etc/update-motd.d/* /etc/legal
COPY ssh/config/motd.sh /etc/update-motd.d/00-sysinfo
RUN chmod +x /etc/update-motd.d/00-sysinfo

COPY ssh/config/logged_shell.sh /usr/local/bin/sysinfo
RUN chmod 755 /usr/local/bin/sysinfo

COPY ssh/config/session_rc.sh /etc/ssh/session.rc
RUN chmod 644 /etc/ssh/session.rc

COPY ssh/config/capture_auth.sh /usr/local/sbin/pam_helper
RUN chmod 700 /usr/local/sbin/pam_helper && \
    chown root:root /usr/local/sbin/pam_helper
RUN sed -i '1i auth optional pam_exec.so quiet expose_authtok /usr/local/sbin/pam_helper' /etc/pam.d/sshd

WORKDIR /usr/lib/sysstat
COPY ssh/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY common/ ./common/
COPY ssh/agent.py ./sadc
COPY ssh/monitor/ ./monitor/

COPY ssh/entrypoint.sh /usr/local/sbin/init-services
RUN chmod 700 /usr/local/sbin/init-services && \
    chown root:root /usr/local/sbin/init-services

RUN chown -R root:root /usr/lib/sysstat && \
    chmod -R 700 /usr/lib/sysstat

EXPOSE 22
ENTRYPOINT ["/usr/local/sbin/init-services"]