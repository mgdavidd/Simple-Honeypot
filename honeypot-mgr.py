#!/usr/bin/env python3
"""
Script para construir imágenes de honeypots y gestionar el stack con docker compose.
"""

import subprocess
import sys
import os
from pathlib import Path

IMAGES = {
    "ssh": {
        "context": "honeypots",
        "dockerfile": "honeypots/ssh/Dockerfile",
        "tag": "honeypot-ssh:v3",
    },
    "http": {
        "context": "honeypots",
        "dockerfile": "honeypots/http/Dockerfile",
        "tag": "honeypot-http:v1",
    },
    # MySQL (comentado para futura personalización)
    "mysql": {
        "context": "honeypots",
        "dockerfile": "honeypots/mysql/Dockerfile",
        "tag": "honeypot-mysql:v1",
    },
}

COMPOSE_FILE = "docker-compose.yml"


def run_command(cmd, description, capture_output=False):
    """Ejecuta un comando y muestra su salida en tiempo real."""
    print(f"\n[+] {description}...")
    try:
        if capture_output:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        else:
            subprocess.run(cmd, shell=True, check=True)
            return "", "", 0
    except subprocess.CalledProcessError as e:
        print(f"Error ejecutando: {cmd}")
        print(f"Código de salida: {e.returncode}")
        if e.stdout:
            print(e.stdout)
        if e.stderr:
            print(e.stderr)
        sys.exit(1)


def image_exists(tag):
    """Verifica si una imagen con la etiqueta dada existe localmente."""
    _, _, rc = run_command(
        f"docker image inspect {tag}",
        f"Verificando existencia de imagen {tag}",
        capture_output=True
    )
    return rc == 0


def build_image(name, context, dockerfile, tag, rebuild=False, no_cache=False):
    """Construye una imagen Docker si no existe o si se solicita rebuild."""
    if not rebuild and image_exists(tag):
        print(f"Imagen {tag} ya existe. Saltando construcción (use --rebuild para forzar).")
        return

    cmd = f"docker build -t {tag} -f {dockerfile} {context}"
    if no_cache:
        cmd += " --no-cache"

    run_command(cmd, f"Construyendo {name} (etiqueta {tag})")


def purge_honeypot_resources():
    """Elimina contenedores dinámicos y volúmenes gestionados por el proyecto."""
    container_ids, _, rc = run_command(
        "docker ps -aq --filter label=honeypot.manager=true",
        "Buscando contenedores dinámicos del honeypot",
        capture_output=True,
    )
    if rc == 0 and container_ids:
        run_command(
            f"docker rm -f -v {container_ids}",
            "Eliminando contenedores dinámicos y sus volúmenes anónimos",
        )

    run_command(
        "docker volume rm http-data-1 http-data-2",
        "Eliminando volúmenes nombrados de los honeypots HTTP",
        capture_output=True,
    )


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Construye imágenes de honeypots y gestiona el stack."
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Reconstruir todas las imágenes aunque ya existan."
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Usar --no-cache en las construcciones."
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Saltar la construcción de imágenes y solo levantar el compose."
    )
    parser.add_argument(
        "--down",
        action="store_true",
        help="Detener y eliminar los contenedores del compose (docker compose down)."
    )
    parser.add_argument(
        "--purge",
        action="store_true",
        help="Detener, eliminar contenedores y también eliminar volúmenes (docker compose down -v)."
    )
    args = parser.parse_args()

    script_dir = Path(__file__).parent.absolute()
    os.chdir(script_dir)

    if not Path(COMPOSE_FILE).exists():
        print(f"No se encontró {COMPOSE_FILE} en el directorio actual.")
        sys.exit(1)

    # Si se pide --purge o --down
    if args.purge or args.down:
        cmd = "docker compose -f {} down".format(COMPOSE_FILE)
        if args.purge:
            cmd += " -v"  # elimina volúmenes
        print(f"\n=== Ejecutando: {cmd} ===")
        run_command(cmd, "Deteniendo y eliminando servicios")
        if args.purge:
            purge_honeypot_resources()
        print("\n✓ Stack detenido" + (" y volúmenes eliminados." if args.purge else "."))
        return

    # Construir imágenes (si no se salta)
    if not args.skip_build:
        print("=== Construcción de imágenes Docker ===")
        for name, cfg in IMAGES.items():
            build_image(
                name=name,
                context=cfg["context"],
                dockerfile=cfg["dockerfile"],
                tag=cfg["tag"],
                rebuild=args.rebuild,
                no_cache=args.no_cache
            )

    # Levantar el stack
    print("\n=== Levantando servicios con docker compose ===")
    run_command(
        f"docker compose -f {COMPOSE_FILE} up -d",
        "Levantando servicios"
    )

    print("\n✓ Stack levantado correctamente.")
    print("   - API disponible en http://api:8000")
    print("   - Revisa logs con: docker compose logs -f")


if __name__ == "__main__":
    main()