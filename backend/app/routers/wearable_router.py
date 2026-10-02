from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .. import schemas, models
from ..database import get_db

router = APIRouter(prefix="/api/v2/wearable", tags=["wearable"])


@router.post("/webhook")
async def wearable_webhook(payload: schemas.WearableWebhookIn, request: Request,
                            db: Session = Depends(get_db)):
    """
    Third-party wearable devices POST readings here. No auth token required
    by design (devices can't easily do interactive login) - but this should
    be replaced with a signed-payload scheme.
    """
    # VULN A08/API10 (Software/Data Integrity Failure, Unsafe Consumption of
    # 3rd-party API): no HMAC/signature header is checked at all. Anyone who
    # can reach this endpoint can inject arbitrary readings for ANY
    # patient_id, since patient_id is trusted straight from the body with
    # no device-to-patient binding check.
    reading = models.WearableReading(
        patient_id=payload.patient_id,
        device_id=payload.device_id,
        metric=payload.metric,
        value=payload.value,
        source_ip=request.client.host if request.client else None,
        raw_payload=str(payload.model_dump()),
    )
    db.add(reading)
    db.commit()
    return {"status": "accepted", "reading_id": reading.id}
