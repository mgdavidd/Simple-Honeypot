from sqlalchemy import Column, String, Integer, DateTime, JSON, Boolean, Text, ForeignKey
from sqlalchemy.orm import relationship
from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Optional

from enum import Enum

from .database import Base

class ServiceType(str, Enum):
    SSH = "ssh"
    HTTP = "http"
    MYSQL = "mysql"


class ContainerStatus(str, Enum):
    RUNNING = "running"
    STOPPED = "stopped"


class Container(Base):
    __tablename__ = "containers"

    id = Column(String, primary_key=True)  # "ssh-1", "http-2", etc
    type = Column(String, nullable=False)
    status = Column(String, default="stopped")  # running, paused, stopped
    replica_id = Column(Integer, nullable=False)  # 1 o 2
    port = Column(Integer, nullable=False)
    persistent = Column(Boolean, default=False)
    
    docker_container_id = Column(String, nullable=True)  # ID real del container
    
    created_at = Column(DateTime, default=lambda: datetime.now())
    destroyed_at = Column(DateTime, nullable=True)
    
    config = Column(JSON, default={})
    
    # Relaciones
    ssh_sessions = relationship("SSHSession", back_populates="container", cascade="all, delete-orphan")
    http_requests = relationship("HTTPRequest", back_populates="container", cascade="all, delete-orphan")
    mysql_queries = relationship("MySQLQuery", back_populates="container", cascade="all, delete-orphan")
    brute_force_alerts = relationship("BruteForceAlert", back_populates="container", cascade="all, delete-orphan")


class SSHSession(Base):
    __tablename__ = "ssh_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    container_id = Column(String, ForeignKey("containers.id"), nullable=False, index=True)
    
    ip = Column(String)
    port = Column(Integer)
    username = Column(String)
    password = Column(String)
    auth_attempts = Column(Integer, default=0)
    credentials_tried = Column(JSON, default=[])
    commands = Column(JSON, default=[])
    
    session_start = Column(DateTime)
    session_end = Column(DateTime)
    
    container = relationship("Container", back_populates="ssh_sessions")


class HTTPRequest(Base):
    __tablename__ = "http_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    container_id = Column(String, ForeignKey("containers.id"), nullable=False)
    
    # Tipo de request
    request_type = Column(String)  # "page_view", "login_attempt", "other_form"
    
    # Request info
    method = Column(String)  # GET, POST, PUT, DELETE, etc
    path = Column(String)
    user_agent = Column(String)
    ip = Column(String)
    
    # Login attempt info (si request_type == "login_attempt")
    username = Column(String, nullable=True)
    password = Column(String, nullable=True)
    login_success = Column(Boolean, default=False)
    
    form_data = Column(JSON, default={})
    
    status_code = Column(Integer)
    response_size = Column(Integer, nullable=True)
    
    timestamp = Column(DateTime, default=datetime.now())
    container = relationship("Container", back_populates="http_requests")


class MySQLQuery(Base):
    __tablename__ = "mysql_queries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    container_id = Column(String, ForeignKey("containers.id"), nullable=False)
    ip = Column(String)
    username = Column(String)
    database_name = Column(String)
    query = Column(String(2000))
    query_type = Column(String)
    sqli_pattern = Column(String)
    detected_tool = Column(String)
    template_name = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

    container = relationship("Container", back_populates="mysql_queries")


class BruteForceAlert(Base):
    __tablename__ = "brute_force_alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    container_id = Column(String, ForeignKey("containers.id"), nullable=False, index=True)
    
    ip = Column(String)
    service_type = Column(String, nullable=False)  # "ssh", "http", "mysql"
    detected_at = Column(DateTime, default=lambda: datetime.now())
    total_attempts = Column(Integer)
    credentials_tried = Column(JSON, default=[])
    action = Column(String)  # "blocked_600s", etc
    
    container = relationship("Container", back_populates="brute_force_alerts")


# -------------- Modelos de configuración (Pydantic v2) --------------

class SSHUserCredential(BaseModel):
    username: str
    password: str


class ServiceConfigSSH(BaseModel):
    ban_seconds: int = 600
    failed_threshold: int = 20
    users: Optional[list[SSHUserCredential]] = None  # None = usar users.txt del build


class ServiceConfigHTTP(BaseModel):
    template: str = "default"
    valid_credentials: dict = {"user": "admin", "password": "admin"}
    ban_seconds: int = 600
    failed_threshold: int = 20
    

class ServiceConfigMySQL(BaseModel):
    database_sql: str = ""
    ban_seconds: int = 600
    failed_threshold: int = 20


class ServiceCreate(BaseModel):
    type: ServiceType
    replica_id: int  # 1 o 2
    port: int = None  # None = autoasignar según defaults
    persistent: bool = False
    config: dict = {}  # JSON flexible


class ServiceUpdate(BaseModel):
    port: int = None
    persistent: bool = None
    config: dict = None


class ContainerResponse(BaseModel):
    id: str
    type: str
    status: str
    replica_id: int
    port: int
    persistent: bool
    docker_container_id: str | None = None
    created_at: datetime
    destroyed_at: datetime | None = None
    config: dict

    model_config = ConfigDict(from_attributes=True)


class SSHSessionResponse(BaseModel):
    id: int
    container_id: str
    ip: str | None = None
    port: int | None = None
    username: str | None = None
    password: str | None = None
    auth_attempts: int
    credentials_tried: list
    commands: list
    session_start: datetime | None = None
    session_end: datetime | None = None

    model_config = ConfigDict(from_attributes=True)

class HTTPRequestResponse(BaseModel):
    id: int
    container_id: str
    request_type: str
    method: Optional[str] = None
    path: Optional[str] = None
    user_agent: Optional[str] = None
    ip: str
    username: Optional[str] = None
    password: Optional[str] = None
    login_success: bool
    form_data: dict
    status_code: Optional[int] = None
    response_size: Optional[int] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class MySQLQueryResponse(BaseModel):
    id: int
    container_id: str
    ip: Optional[str] = None
    username: Optional[str] = None
    database_name: Optional[str] = None
    query: Optional[str] = None
    query_type: Optional[str] = None
    sqli_pattern: Optional[str] = None
    detected_tool: Optional[str] = None
    template_name: Optional[str] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class BruteForceAlertResponse(BaseModel):
    id: int
    container_id: str
    ip: str | None = None
    service_type: str  # NOT NULL en BD
    detected_at: datetime
    total_attempts: int | None = None
    credentials_tried: list
    action: str | None = None

    model_config = ConfigDict(from_attributes=True)
    
# Al final de models.py, antes de los schemas Pydantic:

class AdminUser(Base):
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.now())
    last_login = Column(DateTime, nullable=True)


# Schemas Pydantic
class AdminUserCreate(BaseModel):
    username: str
    password: str

    model_config = ConfigDict(from_attributes=True)


class AdminUserResponse(BaseModel):
    id: int
    username: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)