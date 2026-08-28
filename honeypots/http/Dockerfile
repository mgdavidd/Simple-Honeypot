FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY http/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Código de la aplicación HTTP
COPY http/config.py \
     http/credentials.py \
     http/server.py \
     http/store.py \
     http/template_utils.py \
     ./

COPY http/routes_wordpress.py \
     http/routes_phpmyadmin.py \
     ./

COPY http/templates/ ./templates/

# Módulos comunes
COPY common/ ./common/

RUN mkdir -p /data

ENV FLASK_ENV=production \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data

EXPOSE 5000

CMD ["python", "server.py"]