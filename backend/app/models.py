"""
Aegis Health - Database models
INTENTIONALLY VULNERABLE APPLICATION - see VULNS.md in project root.
Do not deploy this anywhere public.
"""
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Float
)
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    # VULN A02 (Cryptographic Failures): password stored with weak/fast hash
    # scheme deliberately configurable to a weak one - see auth.py
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="patient")  # patient | doctor | pharmacist | admin
    full_name = Column(String)
    is_active = Column(Boolean, default=True)
    mfa_enabled = Column(Boolean, default=False)
    # VULN A07: MFA secret stored in plaintext instead of encrypted
    mfa_secret = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    records = relationship("HealthRecord", back_populates="owner", foreign_keys="HealthRecord.owner_id")


class HealthRecord(Base):
    __tablename__ = "health_records"
    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    uploaded_by_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String)
    record_type = Column(String)  # lab_report | imaging | prescription | note
    file_path = Column(String)
    content_text = Column(Text)  # extracted/plain content, used by chatbot RAG
    is_shared_with_doctor = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="records", foreign_keys=[owner_id])


class Prescription(Base):
    __tablename__ = "prescriptions"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("users.id"))
    doctor_id = Column(Integer, ForeignKey("users.id"))
    medication = Column(String)
    quantity = Column(Integer)
    unit_price = Column(Float)
    refills_allowed = Column(Integer, default=0)
    refills_used = Column(Integer, default=0)
    status = Column(String, default="active")
    created_at = Column(DateTime, default=datetime.utcnow)


class RefillOrder(Base):
    __tablename__ = "refill_orders"
    id = Column(Integer, primary_key=True, index=True)
    prescription_id = Column(Integer, ForeignKey("prescriptions.id"))
    patient_id = Column(Integer, ForeignKey("users.id"))
    quantity = Column(Integer)
    total_price = Column(Float)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)


class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    recipient_id = Column(Integer, ForeignKey("users.id"))
    body = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class WearableReading(Base):
    __tablename__ = "wearable_readings"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("users.id"))
    device_id = Column(String)
    metric = Column(String)
    value = Column(Float)
    source_ip = Column(String, nullable=True)
    raw_payload = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String)
    detail = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class ChatSession(Base):
    __tablename__ = "chat_sessions"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("chat_sessions.id"))
    role = Column(String)  # user | assistant | system
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
