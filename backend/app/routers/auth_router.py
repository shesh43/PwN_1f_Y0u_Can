from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import schemas, models
from ..database import get_db
from ..auth import (
    hash_password, verify_password, create_access_token,
    create_refresh_token, decode_token, get_current_user,
)

router = APIRouter(prefix="/api/v2/auth", tags=["auth"])


@router.post("/register", response_model=schemas.UserOut)
def register(payload: schemas.RegisterIn, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    # VULN API3: role taken directly from client input, no server-side
    # allowlist - a registration request can self-assign role="admin".
    user = models.User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=payload.role or "patient",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.add(models.AuditLog(actor_id=user.id, action="register", detail=f"role={user.role}"))
    db.commit()
    return user


@router.post("/login", response_model=schemas.TokenOut)
def login(payload: schemas.LoginIn, db: Session = Depends(get_db)):
    # VULN-02: no rate limiting / lockout here - brute forceable.
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return schemas.TokenOut(
        access_token=create_access_token(user),
        refresh_token=create_refresh_token(user),
    )


@router.post("/refresh", response_model=schemas.TokenOut)
def refresh(refresh_token: str, db: Session = Depends(get_db)):
    payload = decode_token(refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Wrong token type")
    user = db.query(models.User).filter(models.User.id == int(payload["sub"])).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    # VULN: refresh tokens are never rotated or revoked - old ones stay valid
    # for their full 14-day lifetime even after use.
    return schemas.TokenOut(
        access_token=create_access_token(user),
        refresh_token=create_refresh_token(user),
    )


@router.get("/me", response_model=schemas.UserOut)
def me(user: models.User = Depends(get_current_user)):
    return user
