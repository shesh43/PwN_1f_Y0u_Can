from pydantic import BaseModel, EmailStr, ConfigDict
from typing import Optional
from datetime import datetime


class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: Optional[str] = "patient"  # VULN API3: client-controlled role field (mass assignment)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool


class UserUpdateIn(BaseModel):
    # VULN API3: no field-level allowlist - role is freely settable by client
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class RecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    owner_id: int
    title: str
    record_type: str
    content_text: Optional[str] = None
    is_shared_with_doctor: bool
    created_at: datetime


class RecordCreateIn(BaseModel):
    title: str
    record_type: str
    content_text: str
    is_shared_with_doctor: bool = True


class FetchFromUrlIn(BaseModel):
    title: str
    source_url: str  # VULN A10/API7: SSRF - fetched server-side with no allowlist


class PrescriptionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    patient_id: int
    medication: str
    quantity: int
    unit_price: float
    refills_allowed: int
    refills_used: int
    status: str


class RefillRequestIn(BaseModel):
    prescription_id: int
    quantity: int  # VULN A04/API6: client-controlled quantity, never capped


class MessageIn(BaseModel):
    recipient_id: int
    body: str


class MessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    sender_id: int
    recipient_id: int
    body: str
    created_at: datetime


class WearableWebhookIn(BaseModel):
    # VULN A08/API10: no signature/HMAC field, patient_id trusted from body
    device_id: str
    patient_id: int
    metric: str
    value: float


class ChatIn(BaseModel):
    session_id: Optional[int] = None
    message: str
