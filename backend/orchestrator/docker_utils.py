import os
import re
import socket
import json
import tarfile
import io
from dataclasses import dataclass
from typing import Optional
from pathlib import Path

import docker
from docker.errors import DockerException, NotFound

from .config import DOCKER_IMAGES, RESOURCE_LIMITS
from .network import NetworkManager


@dataclass(slots=True)
class ContainerInfo:
    id: str
    name: str
    image: str
    port: int
    network: str


def is_port_available(port: int) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("0.0.0.0", port))
        sock.close()
        return True
    except OSError:
        return False


class DockerManager:
    def __init__(self):
        self.client = docker.from_env()
        self.networks = NetworkManager(self.client)

    def create_container(
        self,
        service_type: str,
        replica_id: int,
        port: int,
        persistent: bool = False,
        config: Optional[dict] = None,
    ) -> ContainerInfo:
        if not is_port_available(port):
            raise ValueError(f"Port {port} is already in use")

        image = DOCKER_IMAGES.get(service_type)
        if not image:
            raise ValueError(f"Unknown service type: {service_type}")

        try:
            self.client.images.get(image)
        except docker.errors.ImageNotFound:
            raise ValueError(f"Docker image '{image}' not found. Please build it first.")

        limits = RESOURCE_LIMITS.get(service_type, {})
        internal_port = self._get_internal_port(service_type)

        container_name = f"{service_type}-{replica_id}"
        network_name = self.networks.get_network_name()
        self.networks.get_network()

        environment = {
            "API_URL": os.getenv("API_URL", "http://api:8000"),
            "SERVICE_TYPE": service_type,
            "REPLICA_ID": str(replica_id),
        }

        temp_file = None

        if service_type == "mysql":
            if config:
                for key, value in config.items():
                    environment[f"CONFIG_{key.upper()}"] = str(value)

            template_name = config.get("template", "empty") if config else "empty"

            templates_dir = Path("/app/honeypot_templates")
            template_path = templates_dir / f"{template_name}.sql"
            if not template_path.exists():
                raise ValueError(f"Template '{template_name}' not found")

            db_password = config.get("db_password", "password123") if config else "password123"
            db_user     = config.get("db_user", "honeypot")         if config else "honeypot"

            with open(template_path, "r") as f:
                user_sql = f.read()

            _db_re = re.compile(
                r"^\s*(?:"
                r"CREATE\s+DATABASE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`'\"]?(\w+)"
                r"|USE\s+[`'\"]?(\w+)"
                r")[`'\"]?",
                re.IGNORECASE | re.MULTILINE,
            )
            m = _db_re.search(user_sql)
            if m:
                db_name = m.group(1) or m.group(2)
                print(f"[docker] SQL declara BD propia: {db_name}")
            else:
                db_name = "honeypot"
                print(f"[docker] SQL sin BD declarada — usando default: {db_name}")

            setup_sql = (
                f"CREATE DATABASE IF NOT EXISTS `{db_name}`;\n"
                f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'%';\n"
                f"FLUSH PRIVILEGES;\n"
            )

            _tar_buf = io.BytesIO()
            with tarfile.open(fileobj=_tar_buf, mode="w") as _tar:
                for fname, sql in [("00_setup.sql", setup_sql), ("01_init.sql", user_sql)]:
                    data = sql.encode("utf-8")
                    info = tarfile.TarInfo(name=fname)
                    info.size = len(data)
                    _tar.addfile(info, io.BytesIO(data))
            _tar_buf.seek(0)
            temp_file = _tar_buf

            environment.update({
                "MYSQL_ROOT_PASSWORD": os.getenv("MYSQL_ROOT_PASSWORD", "password123"),
                "MYSQL_DATABASE":      db_name,
                "MYSQL_USER":          db_user,
                "MYSQL_PASSWORD":      db_password,
                "TEMPLATE_NAME":       template_name,
            })

            print(f"[docker] MySQL template: {template_name} | DB: {db_name}")

        elif service_type == "http":
            if config:
                for key, value in config.items():
                    # Serializar credenciales a JSON para que el servidor HTTP pueda parsearlo
                    if key == "valid_credentials" and isinstance(value, dict):
                        environment[f"CONFIG_{key.upper()}"] = json.dumps(value)
                    else:
                        environment[f"CONFIG_{key.upper()}"] = str(value)

        elif service_type == "ssh":
            if config:
                for key, value in config.items():
                    if key != "users":  # users va por archivo, no por env var
                        environment[f"CONFIG_{key.upper()}"] = str(value)

            # Si vienen usuarios custom (texto plano "user:pass" por línea),
            # generar users.txt en memoria y copiarlo antes de arrancar.
            # El entrypoint lo leerá desde /tmp/users.txt y ejecutará create_users.sh.
            users_raw = (config or {}).get("users", "").strip()
            if users_raw:
                users_bytes = users_raw.encode("utf-8")
                _tar_buf = io.BytesIO()
                with tarfile.open(fileobj=_tar_buf, mode="w") as _tar:
                    info = tarfile.TarInfo(name="users.txt")
                    info.size = len(users_bytes)
                    _tar.addfile(info, io.BytesIO(users_bytes))
                _tar_buf.seek(0)
                temp_file = _tar_buf
                user_count = len([l for l in users_raw.splitlines() if l.strip()])
                print(f"[docker] SSH: {user_count} usuarios custom preparados")

        print(f"[docker] Creando {container_name} | puerto={port} | image={image}")

        try:
            nano_cpus = int(float(limits.get("cpu", 0.5)) * 1_000_000_000)

            container = self.client.containers.create(
                image=image,
                name=container_name,
                detach=True,
                environment=environment,
                network=network_name,
                ports={f"{internal_port}/tcp": ("0.0.0.0", port)},
                mem_limit=limits.get("memory", "256m"),
                memswap_limit=limits.get("memory", "256m"),
                nano_cpus=nano_cpus,
                pids_limit=limits.get("pids", 50),
                auto_remove=not persistent,
                cap_add=["NET_ADMIN", "NET_RAW"],
            )

            if service_type == "mysql" and temp_file:
                try:
                    container.put_archive("/docker-entrypoint-initdb.d", temp_file)
                    print(f"[docker] SQL templates copiados a {container_name} (00_setup + 01_init)")
                except Exception as e:
                    print(f"[docker] Error copiando SQL templates: {e}")
                    raise

            if service_type == "ssh" and temp_file:
                try:
                    container.put_archive("/tmp", temp_file)
                    print(f"[docker] users.txt copiado a {container_name}")
                except Exception as e:
                    print(f"[docker] Error copiando users.txt: {e}")
                    raise

            container.start()
            print(f"[docker] {container_name} corriendo en puerto {port}")

            return ContainerInfo(
                id=container.id,
                name=container.name,
                image=image,
                port=port,
                network=network_name,
            )

        except docker.errors.ImageNotFound:
            raise ValueError(f"Docker image '{image}' not found")
        except docker.errors.ContainerError as e:
            raise ValueError(f"Container error: {str(e)}")
        except DockerException as e:
            print(f"[docker] Error creando {container_name}: {e}")
            raise ValueError(f"Docker error: {str(e)}")

    def destroy_container(self, container_id: str) -> bool:
        try:
            container = self.client.containers.get(container_id)
            if container.status == "running":
                container.stop(timeout=2)
            container.remove(force=True)
            print(f"[docker] {container_id[:12]} destruido")
            return True
        except NotFound:
            print(f"[docker] {container_id[:12]} no encontrado (ya eliminado)")
            return False
        except DockerException as e:
            if hasattr(e, 'status_code') and e.status_code == 409:
                print(f"[docker] {container_id[:12]} ya está siendo eliminado, se considera destruido")
                return True
            print(f"[docker] Error destruyendo {container_id[:12]}: {e}")
            raise

    def pause_container(self, container_id: str) -> bool:
        try:
            container = self.client.containers.get(container_id)
            container.pause()
            print(f"[docker] {container_id[:12]} pausado")
            return True
        except DockerException as e:
            print(f"[docker] Error pausando {container_id[:12]}: {e}")
            raise

    def unpause_container(self, container_id: str) -> bool:
        try:
            container = self.client.containers.get(container_id)
            container.unpause()
            print(f"[docker] {container_id[:12]} reanudado")
            return True
        except DockerException as e:
            print(f"[docker] Error reanudando {container_id[:12]}: {e}")
            raise

    def get(self, container_id: str):
        try:
            return self.client.containers.get(container_id)
        except NotFound:
            return None

    def list(self, all_containers: bool = False):
        return self.client.containers.list(all=all_containers)

    @staticmethod
    def _get_internal_port(service: str) -> int:
        return {"ssh": 22, "http": 5000, "mysql": 3306}.get(service, 5000)


_manager: Optional[DockerManager] = None

def get_docker_manager() -> DockerManager:
    global _manager
    if _manager is None:
        _manager = DockerManager()
    return _manager