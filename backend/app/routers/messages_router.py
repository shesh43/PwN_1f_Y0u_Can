from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session


from .. import schemas, models
from ..database import get_db
from ..auth import get_current_user

router = APIRouter(prefix="/api/v2/messages", tags=["messages"])


@router.post("", response_model=schemas.MessageOut)
def send_message(payload: schemas.MessageIn, db: Session = Depends(get_db),
                  user: models.User = Depends(get_current_user)):
    msg = models.Message(sender_id=user.id, recipient_id=payload.recipient_id, body=payload.body)
    db.add(msg)
    db.commit()
    db.refresh(msg)
    return msg


@router.get("/thread/{other_user_id}", response_model=list[schemas.MessageOut])
def get_thread(other_user_id: int, db: Session = Depends(get_db),
                user: models.User = Depends(get_current_user)):
    # VULN A01/API1: returns the thread between other_user_id and ANY third
    # party if you pass a user_id query-less variant - here specifically,
    # no check that `user` is actually a participant in this thread at all;
    # any authenticated user can read any two users' conversation.
    msgs = db.query(models.Message).filter(
        ((models.Message.sender_id == other_user_id) | (models.Message.recipient_id == other_user_id))
    ).all()
    return msgs
