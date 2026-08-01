FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*

COPY http/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ../common /app/common

# Copiar todos los módulos del servicio http
COPY http/ /app/

RUN mkdir -p /var/log/honeypot

EXPOSE 5000
CMD ["python3", "-u", "server.py"]