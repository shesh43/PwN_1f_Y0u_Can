from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session


from .. import schemas, models
from ..database import get_db
from ..auth import get_current_user

router = APIRouter(prefix="/api/v2/pharmacy", tags=["pharmacy"])


@router.get("/prescriptions/{patient_id}", response_model=list[schemas.PrescriptionOut])
def list_prescriptions(patient_id: int, db: Session = Depends(get_db),
                        user: models.User = Depends(get_current_user)):
    # VULN A01/API1: no ownership/role check - any user can view any
    # patient's prescriptions by id.
    return db.query(models.Prescription).filter(models.Prescription.patient_id == patient_id).all()


@router.post("/refill")
def request_refill(payload: schemas.RefillRequestIn, db: Session = Depends(get_db),
                    user: models.User = Depends(get_current_user)):
    presc = db.query(models.Prescription).filter(models.Prescription.id == payload.prescription_id).first()
    if not presc:
        raise HTTPException(status_code=404, detail="Prescription not found")

    # VULN A01: no check that presc.patient_id == user.id - any patient can
    # refill (and receive) another patient's prescription.
    # VULN A04/API6 (Broken business flow / Insecure Design): quantity is
    # taken directly from client input and never checked against
    # refills_allowed/refills_used, and unit_price is trusted from the DB
    # record but total is computed without any cap -> free-quantity abuse.
    total_price = presc.unit_price * payload.quantity

    order = models.RefillOrder(
        prescription_id=presc.id,
        patient_id=presc.patient_id,
        quantity=payload.quantity,
        total_price=total_price,
        status="approved",  # VULN: auto-approved, no pharmacist review step
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    return {
        "order_id": order.id,
        "quantity": order.quantity,
        "total_price": order.total_price,
        "status": order.status,
    }
