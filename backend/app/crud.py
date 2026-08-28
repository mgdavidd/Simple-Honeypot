from sqlalchemy.orm import Session
from .time_utils import colombia_now

from .models import Container, SSHSession, HTTPRequest, MySQLQuery, BruteForceAlert
from .models import ServiceCreate, ContainerResponse, ServiceUpdate


class ContainerCRUD:
    @staticmethod
    def create(
        db: Session,
        service: ServiceCreate,
        docker_id: str | None = None,
        status: str = "running",
    ) -> Container:

        container_id = f"{service.type.value}-{service.replica_id}"

        container = (
            db.query(Container)
            .filter(Container.id == container_id)
            .first()
        )

        if container:
            container.type = service.type.value
            container.replica_id = service.replica_id
            container.port = service.port
            container.persistent = service.persistent
            container.docker_container_id = docker_id
            container.status = status
            container.config = service.config or {}

            # Reactivar el servicio
            container.destroyed_at = None

        else:
            container = Container(
                id=container_id,
                type=service.type.value,
                replica_id=service.replica_id,
                port=service.port,
                persistent=service.persistent,
                docker_container_id=docker_id,
                status=status,
                config=service.config or {},
            )

            db.add(container)

        db.commit()
        db.refresh(container)

        return container

    @staticmethod
    def get_by_id(db: Session, container_id: str) -> Container:
        return db.query(Container).filter(Container.id == container_id).first()

    @staticmethod
    def list_all(db: Session) -> list:
        return db.query(Container).all()

    @staticmethod
    def list_by_type(db: Session, service_type) -> list:
        type_val = service_type.value if hasattr(service_type, "value") else service_type
        return db.query(Container).filter(
            Container.type == type_val,
            Container.destroyed_at == None
        ).all()
    @staticmethod
    def update(db: Session, container_id: str, service_update: ServiceUpdate) -> Container:
        container = ContainerCRUD.get_by_id(db, container_id)
        if not container:
            return None

        if service_update.port is not None:
            container.port = service_update.port
        if service_update.persistent is not None:
            container.persistent = service_update.persistent
        if service_update.config is not None:
            container.config = service_update.config

        db.commit()
        db.refresh(container)
        return container

    @staticmethod
    def delete(db: Session, container_id: str):

        container = ContainerCRUD.get_by_id(db, container_id)

        if not container:
            return None

        container.status = "destroyed"
        container.destroyed_at = colombia_now()
        container.docker_container_id = None

        db.commit()

        return container

    @staticmethod
    def update_status(db: Session, container_id: str, status: str):
        container = ContainerCRUD.get_by_id(db, container_id)
        if container:
            container.status = status
            db.commit()
        return container

    @staticmethod
    def update_docker_id(db: Session, container_id: str, docker_id: str):
        container = ContainerCRUD.get_by_id(db, container_id)
        if container:
            container.docker_container_id = docker_id
            db.commit()
        return container