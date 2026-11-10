"""
Auth utilities.
INTENTIONAL VULNS (see VULNS.md):
  - VULN-01: JWT signed with a weak, hardcoded secret (A02 / API8 Security Misconfig)
  - VULN-02: No rate limiting / lockout on login (API4 Unrestricted Resource Consumption)
  - VULN-03: JWT accepts alg "HS256" only at issue time, but the verification
             path trusts the header-declared alg without pinning it -> algorithm
             confusion is exploitable if an RS256 public key is ever exposed
             (kept as a design note; see VULNS.md for the exact repro).
"""
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from .database import get_db
from .models import User

# VULN-01: weak, hardcoded, short JWT secret - a real target would leak this
# via source, .env in a repo, or brute force.
SECRET_KEY = "medivulnx2035"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 14

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# HTTPBearer gives Swagger a simple "paste your token" Authorize box instead
# of a username/password/client_id form - matches our actual JSON login flow.
bearer_scheme = HTTPBearer()


def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)


def hash_password(plain):
    return pwd_context.hash(plain)


def create_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + expires_delta})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(user: User):
    return create_token(
        {"sub": str(user.id), "role": user.role, "type": "access"},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def create_refresh_token(user: User):
    return create_token(
        {"sub": str(user.id), "type": "refresh"},
        timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )


def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Wrong token type")
    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


def require_role(*roles):
    def dep(user: User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return dep
