import os
import bcrypt

from datetime import timedelta
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, Cookie
from sqlalchemy.orm import Session
from dotenv import load_dotenv

load_dotenv()

from .database import get_db
from .models import AdminUser
from .time_utils import colombia_now


SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "your-super-secret-key-change-this-in-production-12345"
)

COOKIE_NAME = os.getenv("COOKIE_NAME", "honeypot_auth_token")


ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440


def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")

    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)

    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    plain_bytes = plain_password.encode("utf-8")

    if len(plain_bytes) > 72:
        plain_bytes = plain_bytes[:72]

    hashed_bytes = hashed_password.encode("utf-8")

    return bcrypt.checkpw(plain_bytes, hashed_bytes)


def create_access_token(
    data: dict,
    expires_delta: timedelta = None
) -> str:
    to_encode = data.copy()

    if expires_delta:
        expire = colombia_now() + expires_delta
    else:
        expire = colombia_now() + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return encoded_jwt


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
    except JWTError:
        return None


def get_current_user(
    token: str,
    db: Session
) -> AdminUser:
    if not token:
        raise HTTPException(
            status_code=401,
            detail="No token provided"
        )

    payload = decode_token(token)

    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    username = payload.get("sub")

    if not username:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    user = (
        db.query(AdminUser)
        .filter(AdminUser.username == username)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    return user

def get_current_user_from_cookie(
    access_token: str | None = Cookie(alias=COOKIE_NAME, default=None),
    db: Session = Depends(get_db)
) -> AdminUser:
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return get_current_user(access_token, db)