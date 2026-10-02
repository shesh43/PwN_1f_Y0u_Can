import os
import uuid
import requests
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session


from .. import schemas, models
from ..database import get_db
from ..auth import get_current_user

router = APIRouter(prefix="/api/v2/records", tags=["records"])

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# VULN: no allowlist of extensions/content-types enforced (Unrestricted File Upload)
ALLOWED_EXT_DOCUMENTED_BUT_NOT_ENFORCED = {".pdf", ".jpg", ".png"}


@router.post("", response_model=schemas.RecordOut)
def create_record(payload: schemas.RecordCreateIn, db: Session = Depends(get_db),
                   user: models.User = Depends(get_current_user)):
    rec = models.HealthRecord(
        owner_id=user.id, uploaded_by_id=user.id, title=payload.title,
        record_type=payload.record_type, content_text=payload.content_text,
        is_shared_with_doctor=payload.is_shared_with_doctor,
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec


@router.post("/upload")
def upload_record(owner_id: int = Form(...), title: str = Form(...),
                   file: UploadFile = File(...), db: Session = Depends(get_db),
                   user: models.User = Depends(get_current_user)):
    # VULN A01/API1: owner_id taken from form data, not from the auth'd user
    # - lets a patient upload/attach a file to ANY patient's record set.
    # VULN A04/A05: no file type / size / content validation -> unrestricted
    # file upload (webshell-style .php/.py upload possible if server ever
    # serves the uploads dir with execution enabled).
    ext = os.path.splitext(file.filename)[1]
    fname = f"{uuid.uuid4().hex}{ext}"
    dest = os.path.join(UPLOAD_DIR, fname)
    with open(dest, "wb") as f:
        f.write(file.file.read())
    rec = models.HealthRecord(
        owner_id=owner_id, uploaded_by_id=user.id, title=title,
        record_type="upload", file_path=fname, content_text="",
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return {"id": rec.id, "stored_as": fname}


@router.post("/fetch-from-url", response_model=schemas.RecordOut)
def fetch_from_url(payload: schemas.FetchFromUrlIn, db: Session = Depends(get_db),
                    user: models.User = Depends(get_current_user)):
    """Lets a patient import a lab report their external provider hosted at a URL."""
    # VULN A10/API7 (SSRF): source_url is fetched server-side with no
    # scheme/host allowlist and no block on internal ranges
    # (127.0.0.1, 169.254.169.254, etc). Classic cloud-metadata SSRF target.
    try:
        resp = requests.get(payload.source_url, timeout=5)
        content = resp.text[:5000]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Fetch failed: {e}")
    rec = models.HealthRecord(
        owner_id=user.id, uploaded_by_id=user.id, title=payload.title,
        record_type="imported", content_text=content,
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec


@router.get("/{record_id}", response_model=schemas.RecordOut)
def get_record(record_id: int, db: Session = Depends(get_db),
                user: models.User = Depends(get_current_user)):
    rec = db.query(models.HealthRecord).filter(models.HealthRecord.id == record_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Not found")
    # VULN A01/API1 (BOLA): no check that rec.owner_id == user.id or that a
    # requesting doctor is actually assigned to this patient. Any
    # authenticated user can read any record by incrementing the id.
    return rec


@router.get("", response_model=list[schemas.RecordOut])
def list_my_records(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    return db.query(models.HealthRecord).filter(models.HealthRecord.owner_id == user.id).all()
