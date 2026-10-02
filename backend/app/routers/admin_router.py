from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from ..auth import get_current_user

router = APIRouter(tags=["admin"])


@router.get("/api/v2/admin/audit-logs")
def get_audit_logs(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    # VULN A01/API5: meant to be admin-only, but role is never checked here.
    # VULN A09 (Logging/Monitoring Failure): sensitive actions like record
    # reads, refill approvals, and role changes are NOT logged at all (only
    # registration is, in auth_router) - so this endpoint under-reports what
    # actually happened, and there's no alerting on anomalies like a role
    # change or bulk record access.
    return db.query(models.AuditLog).all()


# VULN API9 (Improper Inventory Management): an old v1 user-listing endpoint
# was left deployed alongside v2 during a migration and was never
# decommissioned or documented. It predates the auth rework entirely and
# has NO authentication check at all.
# include_in_schema=False means it won't appear in Swagger — you have to
# discover it through recon (directory brute-force, git history, JS analysis).
@router.get("/api/v1/users", include_in_schema=False)
def legacy_list_users(db: Session = Depends(get_db)):
    return [
        {"id": u.id, "email": u.email, "role": u.role, "full_name": u.full_name}
        for u in db.query(models.User).all()
    ]
