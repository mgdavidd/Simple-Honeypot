FROM mysql:8.0

WORKDIR /app

# Instalar Python, pip, net-tools e iptables (Oracle Linux)
RUN microdnf install -y python3 python3-pip net-tools iptables && \
    microdnf clean all

# Directorio para los logs
RUN mkdir -p /var/log/mysql && chown mysql:mysql /var/log/mysql

# Copiar agente y dependencias
COPY mysql/agent.py .
COPY mysql/requirements.txt .
COPY common ./honeypots/common

# Instalar dependencias de Python
RUN pip3 install --no-cache-dir -r requirements.txt

# Configuración MySQL (sin general_log activado)
COPY mysql/general-log.cnf /etc/mysql/conf.d/general-log.cnf

EXPOSE 3306

# El agente espera a que MySQL complete el init antes de activar el log
CMD ["sh", "-c", "docker-entrypoint.sh mysqld & python3 /app/agent.py"]