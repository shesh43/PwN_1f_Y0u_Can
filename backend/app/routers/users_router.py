from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session


from .. import schemas, models
from ..database import get_db
from ..auth import get_current_user

router = APIRouter(prefix="/api/v2/users", tags=["users"])


@router.get("/{user_id}", response_model=schemas.UserOut)
def get_user(user_id: int, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    # VULN API1/API5 (Broken Function/Object Level Auth): any authenticated
    # user, regardless of role, can view any other user's profile by id.
    target = db.query(models.User).filter(models.User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Not found")
    return target


@router.put("/{user_id}", response_model=schemas.UserOut)
def update_user(user_id: int, payload: schemas.UserUpdateIn, db: Session = Depends(get_db),
                 user: models.User = Depends(get_current_user)):
    target = db.query(models.User).filter(models.User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Not found")
    # VULN API1: ownership never checked - user A can edit user B's profile.
    # VULN API3: mass assignment - a "patient" can PUT {"role": "admin"} on
    # their own id and escalate privileges, since role isn't stripped here.
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(target, field, value)
    db.commit()
    db.refresh(target)
    return target


@router.get("", response_model=list[schemas.UserOut])
def list_users(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    # VULN API5: intended admin-only, no role check enforced -> any logged
    # in user can enumerate the full user list.
    return db.query(models.User).all()
