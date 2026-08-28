from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError

from .database import init_db, get_db

app = FastAPI(
    title="Honeypot Manager API",
    version="1.0.0"
)

# permitir a los servicios comunicarse solo por red docker
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    init_db()
    print("[api] Base de datos inicializada")

@app.on_event("shutdown")
def shutdown_event():
    """Destruir todos los contenedores activos cuando la API se cierra."""
    print("[api] Cerrando honeypots...")
    from .database import SessionLocal
    from .crud import ContainerCRUD
    from orchestrator.docker_utils import get_docker_manager
    
    db = SessionLocal()
    try:
        containers = ContainerCRUD.list_all(db)
        docker_mgr = get_docker_manager()
        
        for container in containers:
            if container.docker_container_id:
                try:
                    print(f"[api] Destruyendo {container.id}...")
                    docker_mgr.destroy_container(
                        container.docker_container_id,
                        service_type=container.type,
                        replica_id=container.replica_id,
                    )
                    ContainerCRUD.delete(db, container.id)
                except Exception as e:
                    print(f"[api] Error destruyendo {container.id}: {e}")
    finally:
        db.close()
    
    print("[api] Honeypots cerrados")

from .routes import root, services, logs, auth, templates

app.include_router(root.router)
app.include_router(auth.router)
app.include_router(services.router)
app.include_router(logs.router)
app.include_router(templates.router)