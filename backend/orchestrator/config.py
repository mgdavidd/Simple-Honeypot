import os
from dotenv import load_dotenv

load_dotenv()

# Puertos por defecto (desde env vars)
DEFAULT_PORTS = {
    "ssh": {
        "replica_1": int(os.getenv("SSH_PORT_1", "2222")),
        "replica_2": int(os.getenv("SSH_PORT_2", "2223")),
    },
    "http": {
        "replica_1": int(os.getenv("HTTP_PORT_1", "8081")),
        "replica_2": int(os.getenv("HTTP_PORT_2", "8082")),
    },
    "mysql": {
        "replica_1": int(os.getenv("MYSQL_PORT_1", "3307")),
        "replica_2": int(os.getenv("MYSQL_PORT_2", "3308")),
    },
}

# Imágenes Docker
DOCKER_IMAGES = {
    "ssh": os.getenv("DOCKER_IMAGE_SSH", "honeypot-ssh:v3"),
    "http": os.getenv("DOCKER_IMAGE_HTTP", "honeypot-http:v1"),
    "mysql": os.getenv("DOCKER_IMAGE_MYSQL", "honeypot-mysql:v1"),
}

# Límites de recursos (desde env vars)
RESOURCE_LIMITS = {
    "ssh": {
        "memory": os.getenv("SSH_MEMORY", "256m"),
        "cpu": float(os.getenv("SSH_CPU", "0.5")),
        "pids": int(os.getenv("SSH_PIDS", "200")),
    },
    "http": {
        "memory": os.getenv("HTTP_MEMORY", "128m"),
        "cpu": float(os.getenv("HTTP_CPU", "0.25")),
        "pids": int(os.getenv("HTTP_PIDS", "50")),
    },
    "mysql": {
        "memory": os.getenv("MYSQL_MEMORY", "512m"),
        "cpu": float(os.getenv("MYSQL_CPU", "1.0")),
        "pids": int(os.getenv("MYSQL_PIDS", "100")),
    },
}

# Thresholds de seguridad (desde env vars)
SECURITY_CONFIG = {
    "ssh": {
        "ban_seconds": int(os.getenv("SSH_BAN_SECONDS", "600")),
        "failed_threshold": int(os.getenv("SSH_FAILED_THRESHOLD", "20")),
    },
    "http": {
        "ban_seconds": int(os.getenv("HTTP_BAN_SECONDS", "600")),
        "failed_threshold": int(os.getenv("HTTP_FAILED_THRESHOLD", "20")),
        "rate_limit_threshold": int(os.getenv("HTTP_RATE_LIMIT_THRESHOLD", "30")),
        "rate_limit_window": int(os.getenv("HTTP_RATE_LIMIT_WINDOW", "15")),
    },
    "mysql": {
        "ban_seconds": int(os.getenv("MYSQL_BAN_SECONDS", "600")),
        "failed_threshold": int(os.getenv("MYSQL_FAILED_THRESHOLD", "20")),
    },
}

MAX_REPLICAS = 2