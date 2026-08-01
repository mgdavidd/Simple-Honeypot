from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from ..database import get_db
from ..models import (
    SSHSession, HTTPRequest, MySQLQuery, BruteForceAlert,
    SSHSessionResponse, HTTPRequestResponse, MySQLQueryResponse, BruteForceAlertResponse,
    AdminUser
)
from ..crud import ContainerCRUD
from ..auth import get_current_user_from_cookie

router = APIRouter()


@router.post("/api/logs", status_code=201)
def add_log(payload: dict, db: Session = Depends(get_db)):
    service_id = payload.get("service_id")
    data = payload.get("data", {})

    if not service_id or not data:
        raise HTTPException(status_code=400, detail="Falta 'service_id' o 'data'")

    container = ContainerCRUD.get_by_id(db, service_id)
    if not container or container.destroyed_at is not None:
        raise HTTPException(status_code=404, detail="Contenedor no encontrado o inactivo")

    service_type = service_id.split("-")[0]
    if service_type not in ["ssh", "http", "mysql"]:
        raise HTTPException(status_code=400, detail="Tipo de servicio no soportado")

    def parse_dt(value):
        if value:
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                pass
        return datetime.now()

    try:
        log_entry = None

        if "total_attempts" in data and "credentials_tried" in data:
            log_entry = BruteForceAlert(
                container_id=service_id,
                ip=data.get("ip"),
                service_type=service_type,
                detected_at=parse_dt(data.get("detected_at")),
                total_attempts=data.get("total_attempts"),
                credentials_tried=data.get("credentials_tried", []),
                action=data.get("action"),
            )
        elif service_type == "ssh":
            credentials = data.get("credentials_tried", [])
            accepted_password = (
                data.get("accepted_password")
                or data.get("password")
                or next(
                    (c.get("password") for c in reversed(credentials)
                     if c.get("username") == data.get("accepted_username")),
                    None
                )
                or (credentials[-1].get("password") if credentials else None)
            )
            log_entry = SSHSession(
                container_id=service_id,
                ip=data.get("ip"),
                port=data.get("port"),
                username=data.get("username") or data.get("accepted_username"),
                password=accepted_password,
                auth_attempts=data.get("auth_attempts", 0),
                credentials_tried=credentials,
                commands=data.get("commands", []),
                session_start=parse_dt(data.get("connection_time")),
                session_end=datetime.now(),
            )
        elif service_type == "http":
            log_entry = HTTPRequest(
                container_id=service_id,
                request_type=data.get("request_type", "other_form"),
                method=data.get("method"),
                path=data.get("path"),
                user_agent=data.get("user_agent"),
                ip=data.get("ip"),
                username=data.get("username"),
                password=data.get("password"),
                login_success=data.get("login_success", False),
                form_data=data.get("form_data", {}),
                status_code=data.get("status_code"),
                response_size=data.get("response_size"),
                timestamp=parse_dt(data.get("timestamp")),
            )
        elif service_type == "mysql":
            log_entry = MySQLQuery(
                container_id=service_id,
                ip=data.get("ip"),
                username=data.get("username", "unknown"),
                database_name=data.get("database_name", "unknown"),
                query=data.get("query", ""),
                query_type=data.get("query_type", "other"),
                sqli_pattern=data.get("sqli_pattern", "none"),
                detected_tool=data.get("detected_tool", "none"),
                template_name=data.get("template_name", ""),
                timestamp=parse_dt(data.get("timestamp")),
            )

        if not log_entry:
            raise HTTPException(status_code=400, detail="No se pudo crear el log")

        db.add(log_entry)
        db.commit()
        return {"status": "ok"}

    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/logs")
def get_logs(
    service_type: str = None,
    service_id: str = None,
    request_type: str = None,          # para HTTP
    query_type: str = None,            # para MySQL
    sqli_pattern: str = None,          # para MySQL
    detected_tool: str = None,         # para MySQL
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user_from_cookie),
):
    """
    Obtener logs. Prioridad: service_type explícito > detección desde service_id > resumen general
    """

    # 1. BRUTEFORCE: verificar primero (tiene prioridad)
    if service_type == "bruteforce":
        q = db.query(BruteForceAlert)
        if service_id:
            q = q.filter(BruteForceAlert.container_id == service_id)
        logs = q.order_by(BruteForceAlert.detected_at.desc()).limit(limit).all()
        return {
            "type": "bruteforce",
            "count": len(logs),
            "logs": [BruteForceAlertResponse.model_validate(l) for l in logs]
        }

    # 2. Si no es bruteforce explícitamente, revisar otros tipos
    if service_type == "http" or (service_id and service_id.startswith("http")):
        q = db.query(HTTPRequest)
        if service_id:
            q = q.filter(HTTPRequest.container_id == service_id)
        if request_type:
            q = q.filter(HTTPRequest.request_type == request_type)
        logs = q.order_by(HTTPRequest.timestamp.desc()).limit(limit).all()
        return {
            "type": "http",
            "count": len(logs),
            "logs": [HTTPRequestResponse.model_validate(l) for l in logs]
        }

    if service_type == "ssh" or (service_id and service_id.startswith("ssh")):
        q = db.query(SSHSession)
        if service_id:
            q = q.filter(SSHSession.container_id == service_id)
        logs = q.order_by(SSHSession.session_start.desc()).limit(limit).all()
        return {
            "type": "ssh",
            "count": len(logs),
            "logs": [SSHSessionResponse.model_validate(l) for l in logs]
        }

    if service_type == "mysql" or (service_id and service_id.startswith("mysql")):
        q = db.query(MySQLQuery)
        if service_id:
            q = q.filter(MySQLQuery.container_id == service_id)
        if query_type:
            q = q.filter(MySQLQuery.query_type == query_type)
        if sqli_pattern and sqli_pattern != "all":
            q = q.filter(MySQLQuery.sqli_pattern == sqli_pattern)
        if detected_tool:
            q = q.filter(MySQLQuery.detected_tool == detected_tool)
        logs = q.order_by(MySQLQuery.timestamp.desc()).limit(limit).all()
        return {
            "type": "mysql",
            "count": len(logs),
            "logs": [MySQLQueryResponse.model_validate(l) for l in logs]
        }

    # 3. Sin filtros: resumen general
    return {
        "ssh":        db.query(SSHSession).count(),
        "http":       db.query(HTTPRequest).count(),
        "mysql":      db.query(MySQLQuery).count(),
        "bruteforce": db.query(BruteForceAlert).count(),
    }


@router.delete("/api/logs/cleanup", status_code=200)
def cleanup_all_logs(
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user_from_cookie),
):
    try:
        ssh  = db.query(SSHSession).delete()
        http = db.query(HTTPRequest).delete()
        msql = db.query(MySQLQuery).delete()
        bf   = db.query(BruteForceAlert).delete()
        db.commit()
        return {"status": "ok", "deleted": {"ssh": ssh, "http": http, "mysql": msql, "bruteforce": bf}}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/api/logs/cleanup/{service_id}", status_code=200)
def cleanup_logs_by_service(
    service_id: str,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(get_current_user_from_cookie),
):
    try:
        ssh  = db.query(SSHSession).filter(SSHSession.container_id == service_id).delete()
        http = db.query(HTTPRequest).filter(HTTPRequest.container_id == service_id).delete()
        msql = db.query(MySQLQuery).filter(MySQLQuery.container_id == service_id).delete()
        bf   = db.query(BruteForceAlert).filter(BruteForceAlert.container_id == service_id).delete()
        db.commit()
        return {"status": "ok", "deleted": {"ssh": ssh, "http": http, "mysql": msql, "bruteforce": bf}}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))