from fastapi import APIRouter, Depends, HTTPException, Response, Cookie
from sqlalchemy.orm import Session
from datetime import datetime
from pydantic import BaseModel
import os
from dotenv import load_dotenv

load_dotenv()


from ..database import get_db
from ..models import AdminUser, AdminUserCreate, AdminUserResponse
from ..auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user_from_cookie,
)

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


COOKIE_NAME = os.getenv("COOKIE_NAME", "honeypot_auth_token")

# LOCALHOST / DESARROLLO
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "False").lower() == "True"

# PRODUCCIÓN HTTPS:
# COOKIE_SECURE = True


def set_auth_cookie(response: Response, access_token: str):
    response.set_cookie(
        key=COOKIE_NAME,
        value=access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=60 * 60 * 24,
        path="/",
    )


def delete_auth_cookie(response: Response):
    response.delete_cookie(
        key=COOKIE_NAME,
        path="/",
    )


@router.get("/api/auth/check")
def check_setup(
    db: Session = Depends(get_db),
    access_token: str | None = Cookie(alias=COOKIE_NAME, default=None),
):
    user_count = db.query(AdminUser).count()
    if user_count == 0:
        return {"setup_required": True, "authenticated": False, "users_count": 0}

    authenticated = False
    if access_token:
        try:
            get_current_user_from_cookie(access_token=access_token, db=db)
            authenticated = True
        except HTTPException:
            authenticated = False

    return {"setup_required": False, "authenticated": authenticated, "users_count": user_count}


@router.post("/api/auth/setup")
def setup_admin(
    user: AdminUserCreate,
    response: Response,
    db: Session = Depends(get_db),
):
    user_count = db.query(AdminUser).count()

    if user_count > 0:
        raise HTTPException(
            status_code=409,
            detail="Admin user already exists"
        )

    if len(user.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters"
        )

    hashed_password = hash_password(user.password)

    db_user = AdminUser(
        username=user.username,
        password_hash=hashed_password,
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    access_token = create_access_token({
        "sub": db_user.username
    })

    set_auth_cookie(response, access_token)

    return {
        "message": "Admin user created successfully",
        "user": AdminUserResponse.from_orm(db_user),
    }


@router.post("/api/auth/login")
def login(credentials: LoginRequest, response: Response, db: Session = Depends(get_db)):
    """Login con usuario y contraseña."""
    user = db.query(AdminUser).filter(AdminUser.username == credentials.username).first()
    if not user or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user.last_login = datetime.now()
    db.commit()
    
    access_token = create_access_token({"sub": user.username})
    
    # ⭐ Establecer cookie HttpOnly (como en setup_admin)
    set_auth_cookie(response, access_token)
    
    return {
        "message": "Login successful",
        "access_token": access_token,  # Frontend recibe token pero NO lo usa (cookie se envía automáticamente)
        "token_type": "bearer",
        "user": AdminUserResponse.from_orm(user)
    }


@router.post("/api/auth/logout")
def logout(response: Response):
    delete_auth_cookie(response)

    return {
        "message": "Logged out successfully"
    }


@router.get("/api/auth/me")
def get_current_user_info(
    current_user: AdminUser = Depends(get_current_user_from_cookie),
):
    return AdminUserResponse.from_orm(current_user)