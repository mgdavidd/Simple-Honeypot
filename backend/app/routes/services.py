from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import AdminUser, Container
from ..auth import get_current_user_from_cookie
from ..time_utils import colombia_now

router = APIRouter()
def _validate_ssh_users(users_raw: str) -> list:
    """Valida formato user:password por linea. Retorna lista de errores."""
    errors = []
    lines = [l.strip() for l in users_raw.strip().splitlines() if l.strip()]
    if not lines:
        errors.append("Debes definir al menos un usuario")
        return errors
    for i, line in enumerate(lines, 1):
        parts = line.split(":", 1)
        if len(parts) != 2:
            errors.append(f"Linea {i}: formato invalido '{line}' (esperado usuario:contrasena)")
            continue
        username, password = parts
        if not username.strip():
            errors.append(f"Linea {i}: el nombre de usuario no puede estar vacio")
        if not password.strip():
            errors.append(f"Linea {i}: la contrasena no puede estar vacia")
        if " " in username or "\t" in username:
            errors.append(f"Linea {i}: el usuario no puede contener espacios")
    return errors



# Mapeo de estados Docker → estados internos
_DOCKER_STATUS_MAP = {
    "running": "running",
    "paused": "paused",
    "exited": "stopped",
    "dead": "stopped",
    "created": "stopped",
    "restarting": "running",
    "removing": "stopped",
}


def _sync_container_status(container: Container, db: Session) -> str:
    if not container.docker_container_id or container.destroyed_at is not None:
        return container.status

    from orchestrator.docker_utils import get_docker_manager
    from docker.errors import DockerException

    try:
        docker_container = get_docker_manager().get(container.docker_container_id)
        if docker_container is None:
            if container.status != "stopped":
                print(f"[sync] {container.id}: no encontrado en Docker, marcando como stopped")
                container.status = "stopped"
                container.docker_container_id = None
                db.commit()
            return "stopped"

        docker_status = docker_container.status
        mapped_status = _DOCKER_STATUS_MAP.get(docker_status, "stopped")

        if mapped_status != container.status:
            print(
                f"[sync] {container.id}: BD='{container.status}' → "
                f"Docker='{docker_status}' ({mapped_status}), actualizando BD"
            )
            container.status = mapped_status
            db.commit()

        return mapped_status

    except DockerException as e:
        print(f"[sync] {container.id}: error consultando Docker: {e}")
        return container.status


def _get_container(db, service_id, require_active=False):
    c = db.query(Container).filter(Container.id == service_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Service not found")
    if require_active and c.destroyed_at is not None:
        raise HTTPException(status_code=404, detail="Service not found or destroyed")
    return c


def _serialize(s):
    return {
        "id": s.id,
        "type": s.type,
        "status": s.status,
        "replica_id": s.replica_id,
        "port": s.port,
        "persistent": s.persistent,
        "docker_container_id": s.docker_container_id,
        "config": s.config,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


@router.get("/api/services")
def list_services(
    service_type: str = None,
    current_user: AdminUser = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    query = db.query(Container)
    if service_type:
        query = query.filter(Container.type == service_type)
    services = query.all()

    for svc in services:
        _sync_container_status(svc, db)

    return {"count": len(services), "services": [_serialize(s) for s in services]}


@router.get("/api/services/{service_id}")
def get_service(
    service_id: str,
    current_user: AdminUser = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    return _serialize(_get_container(db, service_id))


# Guardar config sin levantar contenedor
@router.post("/api/services/{service_id}/setup-config")
def setup_config(
    service_id: str,
    body: dict,
    current_user: AdminUser = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    service_type = body.get("type")
    replica_id = body.get("replica_id")
    if not service_type or replica_id is None:
        raise HTTPException(status_code=400, detail="type and replica_id are required")

    existing = db.query(Container).filter(Container.id == service_id).first()

    # Verificar si hay un contenedor activo real
    if existing and existing.docker_container_id and existing.destroyed_at is None:
        from orchestrator.docker_utils import get_docker_manager
        docker_mgr = get_docker_manager()
        if docker_mgr.get(existing.docker_container_id) is not None:
            raise HTTPException(
                status_code=409,
                detail="Service is running. Use /reconfigure instead."
            )
        else:
            # El contenedor no existe realmente, limpiar el ID y permitir configuración
            existing.docker_container_id = None
            existing.status = "stopped"
            db.commit()

    try:
        if existing:
            existing.type = service_type
            existing.replica_id = replica_id
            existing.port = body.get("port")
            existing.persistent = body.get("persistent", False)
            existing.config = body.get("config", {})
            existing.status = "configured"
            existing.destroyed_at = None
            existing.docker_container_id = None
        else:
            db.add(Container(
                id=service_id,
                type=service_type,
                replica_id=replica_id,
                port=body.get("port"),
                persistent=body.get("persistent", False),
                config=body.get("config", {}),
                status="configured",
                docker_container_id=None,
            ))
        db.commit()
        return {"id": service_id, "status": "configured"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# Lanzar contenedor desde config guardada
@router.post("/api/services/{service_id}/launch")
def launch_service(
    service_id: str,
    current_user: AdminUser = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    from orchestrator.docker_utils import get_docker_manager
    from orchestrator.config import DEFAULT_PORTS

    container = _get_container(db, service_id)
    if container.status != "configured":
        raise HTTPException(status_code=400, detail=f"Expected status 'configured', got '{container.status}'")

    try:
        info = get_docker_manager().create_container(
            service_type=container.type,
            replica_id=container.replica_id,
            port=container.port or DEFAULT_PORTS[container.type][f"replica_{container.replica_id}"],
            persistent=container.persistent,
            config=container.config,
        )
        container.docker_container_id = info.id
        container.status = "running"
        if not container.port:
            container.port = info.port
        db.commit()
        return {"id": service_id, "status": "running", "port": container.port}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# Crear directo (sin pre-config)
@router.post("/api/services")
def create_service(
    body: dict,
    current_user: AdminUser = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    from orchestrator.docker_utils import get_docker_manager
    from orchestrator.config import DEFAULT_PORTS

    service_type = body.get("type")
    replica_id = body.get("replica_id")
    if not service_type or replica_id is None:
        raise HTTPException(status_code=400, detail="type and replica_id are required")

    container_id = f"{service_type}-{replica_id}"
    existing = db.query(Container).filter(
        Container.id == container_id, Container.destroyed_at == None
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"{container_id} already exists")

    try:
        port = body.get("port")
        persistent = body.get("persistent", False)
        config = body.get("config", {})

        if service_type == "ssh" and config.get("users"):
            errs = _validate_ssh_users(config["users"])
            if errs:
                raise HTTPException(status_code=422, detail={"users_errors": errs})

        info = get_docker_manager().create_container(
            service_type=service_type,
            replica_id=replica_id,
            port=port or DEFAULT_PORTS[service_type][f"replica_{replica_id}"],
            persistent=persistent,
            config=config,
        )
        db.add(Container(
            id=container_id, type=service_type, status="running",
            replica_id=replica_id, port=info.port, persistent=persistent,
            docker_container_id=info.id, config=config,
        ))
        db.commit()
        return {"id": container_id, "status": "running", "port": info.port}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# Reconfigurar servicio corriendo: destruye + recrea
@router.patch("/api/services/{service_id}/reconfigure")
def reconfigure_service(
    service_id: str,
    body: dict,
    current_user: AdminUser = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    from orchestrator.docker_utils import get_docker_manager
    from orchestrator.config import DEFAULT_PORTS

    container = _get_container(db, service_id, require_active=True)
    if container.status not in ("running", "paused"):
        raise HTTPException(status_code=400, detail=f"Cannot reconfigure status '{container.status}'")

    try:
        docker_mgr = get_docker_manager()
        # Solo destruir si el contenedor realmente existe en Docker
        if container.docker_container_id:
            existing_container = docker_mgr.get(container.docker_container_id)
            if existing_container is not None:
                docker_mgr.destroy_container(
                    container.docker_container_id,
                    service_type=container.type,
                    replica_id=container.replica_id,
                )
            else:
                # El contenedor ya no existe, limpiar el ID en BD
                container.docker_container_id = None

        new_port = body.get("port") or container.port
        new_persistent = body.get("persistent") if "persistent" in body else container.persistent
        new_config = body.get("config") or container.config

        if container.type == "ssh" and new_config.get("users"):
            errs = _validate_ssh_users(new_config["users"])
            if errs:
                raise HTTPException(status_code=422, detail={"users_errors": errs})

        info = docker_mgr.create_container(
            service_type=container.type,
            replica_id=container.replica_id,
            port=new_port or DEFAULT_PORTS[container.type][f"replica_{container.replica_id}"],
            persistent=new_persistent,
            config=new_config,
        )
        container.port = info.port
        container.persistent = new_persistent
        container.docker_container_id = info.id
        container.status = "running"
        container.config = new_config
        db.commit()
        return {"id": service_id, "status": "running", "port": container.port}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# Pausar (persistent) o destruir (no-persistent)
@router.patch("/api/services/{service_id}/stop")
def stop_service(
    service_id: str,
    current_user: AdminUser = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    from orchestrator.docker_utils import get_docker_manager

    container = _get_container(db, service_id, require_active=True)
    if container.status not in ("running",):
        raise HTTPException(status_code=400, detail=f"Cannot stop status '{container.status}'")

    try:
        docker_mgr = get_docker_manager()
        if container.persistent:
            docker_mgr.pause_container(container.docker_container_id)
            container.status = "paused"
            action = "paused"
        else:
            docker_mgr.destroy_container(
                container.docker_container_id,
                service_type=container.type,
                replica_id=container.replica_id,
            )
            container.destroyed_at = colombia_now()
            container.status = "destroyed"
            container.docker_container_id = None
            action = "destroyed"
        db.commit()
        return {"action": action, "new_status": container.status}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# Reanudar pausado (solo persistent)
@router.patch("/api/services/{service_id}/start")
def start_service(
    service_id: str,
    current_user: AdminUser = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    from orchestrator.docker_utils import get_docker_manager

    container = _get_container(db, service_id)
    if container.status != "paused":
        raise HTTPException(status_code=400, detail="Service is not paused")

    try:
        get_docker_manager().unpause_container(container.docker_container_id)
        container.status = "running"
        db.commit()
        return {"status": "running"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# Recrear persistent destruido con config guardada
@router.post("/api/services/{service_id}/recreate")
def recreate_service(
    service_id: str,
    current_user: AdminUser = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    from orchestrator.docker_utils import get_docker_manager

    container = _get_container(db, service_id)
    if not container.persistent:
        raise HTTPException(status_code=400, detail="Only persistent services can be recreated")
    if container.destroyed_at is None:
        raise HTTPException(status_code=400, detail="Service is not destroyed")

    try:
        info = get_docker_manager().create_container(
            service_type=container.type,
            replica_id=container.replica_id,
            port=container.port,
            persistent=container.persistent,
            config=container.config,
        )
        container.docker_container_id = info.id
        container.status = "running"
        container.destroyed_at = None
        db.commit()
        return {"id": service_id, "status": "running"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# Eliminar permanentemente
@router.delete("/api/services/{service_id}")
def delete_service(
    service_id: str,
    current_user: AdminUser = Depends(get_current_user_from_cookie),
    db: Session = Depends(get_db)
):
    from orchestrator.docker_utils import get_docker_manager

    container = _get_container(db, service_id)
    try:
        if container.docker_container_id:
            try:
                get_docker_manager().destroy_container(
                    container.docker_container_id,
                    service_type=container.type,
                    replica_id=container.replica_id,
                )
            except Exception as e:
                print(f"[api] Warning destroying container: {e}")

        if container.status == "configured":
            db.delete(container)
        else:
            container.status = "destroyed"
            container.destroyed_at = colombia_now()
            container.docker_container_id = None
        db.commit()
        return {"status": "ok"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))