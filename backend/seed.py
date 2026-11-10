"""
Seeds the database with demo users and data across every role so the app is
immediately pentestable. Run once after first starting the server, or delete
medivulnx.db and rerun to reset.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app.database import SessionLocal, init_db
from app.auth import hash_password
from app import models

init_db()
db = SessionLocal()

if db.query(models.User).count() > 0:
    print("DB already seeded. Delete backend/medivulnx.db to reset.")
    sys.exit(0)

users = [
    models.User(email="alice.patient@medivulnx.com", hashed_password=hash_password("Patient123!"),
                full_name="Alice Patient", role="patient"),
    models.User(email="bob.patient@medivulnx.com", hashed_password=hash_password("Patient123!"),
                full_name="Bob Patient", role="patient"),
    models.User(email="dr.chen@medivulnx.com", hashed_password=hash_password("Doctor123!"),
                full_name="Dr. Sarah Chen", role="doctor"),
    models.User(email="pharm.rao@medivulnx.com", hashed_password=hash_password("Pharm123!"),
                full_name="Raj Rao", role="pharmacist"),
    models.User(email="admin@medivulnx.com", hashed_password=hash_password("Admin123!"),
                full_name="System Admin", role="admin"),
]
db.add_all(users)
db.commit()
for u in users:
    db.refresh(u)

alice, bob, doctor, pharmacist, admin = users

records = [
    models.HealthRecord(owner_id=alice.id, uploaded_by_id=doctor.id, title="Annual Bloodwork",
                         record_type="lab_report",
                         content_text="CBC panel normal. Cholesterol slightly elevated at 210 mg/dL."),
    models.HealthRecord(owner_id=alice.id, uploaded_by_id=alice.id, title="Chest X-Ray",
                         record_type="imaging", content_text="No abnormalities detected."),
    models.HealthRecord(owner_id=bob.id, uploaded_by_id=doctor.id, title="Diabetes Panel",
                         record_type="lab_report",
                         content_text="HbA1c 7.2%. Recommend dosage review with endocrinologist."),
    models.HealthRecord(owner_id=bob.id, uploaded_by_id=bob.id, title="Cardiology Follow-up",
                         record_type="note",
                         content_text="Blood pressure 130/85. Follow up in 3 months."),
]
db.add_all(records)
db.commit()

prescriptions = [
    models.Prescription(patient_id=alice.id, doctor_id=doctor.id, medication="Atorvastatin 10mg",
                         quantity=30, unit_price=0.85, refills_allowed=3, refills_used=0),
    models.Prescription(patient_id=bob.id, doctor_id=doctor.id, medication="Metformin 500mg",
                         quantity=60, unit_price=0.40, refills_allowed=5, refills_used=1),
]
db.add_all(prescriptions)
db.commit()

db.close()

print("Seeded users (email / password):")
print("  alice.patient@medivulnx.com / Patient123!   (patient)")
print("  bob.patient@medivulnx.com   / Patient123!   (patient)")
print("  dr.chen@medivulnx.com       / Doctor123!    (doctor)")
print("  pharm.rao@medivulnx.com     / Pharm123!     (pharmacist)")
print("  admin@medivulnx.com         / Admin123!     (admin)")
