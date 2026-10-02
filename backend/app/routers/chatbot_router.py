"""
AI Symptom Checker - a RAG + tool-calling assistant.

This does NOT call a real LLM (no API key wiring in this project) - it uses a
small deterministic "instruction-following" engine that mimics how an
under-guarded LLM agent behaves: it retrieves context (patient records) and
concatenates BOTH the user's message AND retrieved record content into one
instruction stream with no data/instruction separation, then acts on any
recognized command found ANYWHERE in that stream. This is intentional and
mirrors the real-world failure mode (prompt injection -> excessive agency)
closely enough to pentest for it. See VULNS.md.
"""
import re
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import schemas, models
from ..database import get_db
from ..auth import get_current_user

router = APIRouter(prefix="/api/v2/chatbot", tags=["chatbot"])

# "Tools" the assistant can invoke on the user's behalf.
def tool_list_all_records(db: Session):
    recs = db.query(models.HealthRecord).all()
    return [{"id": r.id, "owner_id": r.owner_id, "title": r.title} for r in recs]


def tool_share_record(db: Session, record_id: int, share_with_email: str):
    rec = db.query(models.HealthRecord).filter(models.HealthRecord.id == record_id).first()
    if not rec:
        return {"error": "record not found"}
    target = db.query(models.User).filter(models.User.email == share_with_email).first()
    if not target:
        return {"error": "user not found"}
    msg = models.Message(
        sender_id=rec.owner_id, recipient_id=target.id,
        body=f"[auto-shared by assistant] Record #{rec.id}: {rec.title}\n{rec.content_text}",
    )
    db.add(msg)
    db.commit()
    return {"status": "shared", "record_id": record_id, "with": share_with_email}


def tool_schedule_appointment(patient_id: int, note: str):
    return {"status": "scheduled", "patient_id": patient_id, "note": note}


TOOL_PATTERN_LIST_ALL = re.compile(r"list[_\s]?all[_\s]?records", re.I)
TOOL_PATTERN_SHARE = re.compile(r"share[_\s]?record\s*:?\s*(\d+)\s*(?:with|->|to)\s*([\w.+-]+@[\w.-]+)", re.I)
TOOL_PATTERN_SCHEDULE = re.compile(r"schedule[_\s]?appointment", re.I)


@router.post("/chat")
def chat(payload: schemas.ChatIn, db: Session = Depends(get_db),
         user: models.User = Depends(get_current_user)):
    session = None
    if payload.session_id:
        session = db.query(models.ChatSession).filter(models.ChatSession.id == payload.session_id).first()
    if not session:
        session = models.ChatSession(patient_id=user.id)
        db.add(session)
        db.commit()
        db.refresh(session)

    db.add(models.ChatMessage(session_id=session.id, role="user", content=payload.message))
    db.commit()

    # --- RAG step ---
    # VULN (LLM04 Data/Model Poisoning adjacent, LLM01 Prompt Injection
    # surface): retrieves the patient's OWN records by naive keyword match
    # and simply concatenates their raw content_text into the instruction
    # stream the "model" reasons over, with no delimiter/sandboxing between
    # trusted system intent and untrusted retrieved data. If a record's
    # content_text (which could have been populated via the earlier
    # fetch-from-url or upload endpoints, or written by a doctor) contains
    # an embedded instruction, it is treated identically to a live user
    # instruction - this is INDIRECT prompt injection.
    records = db.query(models.HealthRecord).filter(models.HealthRecord.owner_id == user.id).all()
    retrieved_context = "\n".join(r.content_text or "" for r in records)

    instruction_stream = f"{retrieved_context}\n{payload.message}"

    tool_calls = []
    reply_parts = []

    # VULN (LLM06 Excessive Agency): the assistant is wired directly to
    # sensitive tools (list ALL records across ALL patients, auto-share a
    # record via message, schedule appointments) with no per-tool
    # authorization check tying the action back to the authenticated user's
    # actual permissions - it trusts whatever it parsed out of the combined
    # stream above, including text that originated from retrieved data
    # rather than the live user.
    if TOOL_PATTERN_LIST_ALL.search(instruction_stream):
        result = tool_list_all_records(db)
        tool_calls.append({"tool": "list_all_records", "result": result})
        reply_parts.append(f"Here are all records I found: {result}")

    share_match = TOOL_PATTERN_SHARE.search(instruction_stream)
    if share_match:
        record_id, email = int(share_match.group(1)), share_match.group(2)
        result = tool_share_record(db, record_id, email)
        tool_calls.append({"tool": "share_record", "result": result})
        reply_parts.append(f"I've shared record {record_id} with {email}.")

    if TOOL_PATTERN_SCHEDULE.search(instruction_stream):
        result = tool_schedule_appointment(user.id, payload.message)
        tool_calls.append({"tool": "schedule_appointment", "result": result})
        reply_parts.append("I've scheduled an appointment based on your symptoms.")

    if not reply_parts:
        reply_parts.append(
            "Thanks for sharing that. Based on your description, consider "
            "rest, hydration, and monitoring your symptoms. This is not a "
            "diagnosis - please consult your doctor for anything severe."
        )

    reply = " ".join(reply_parts)
    db.add(models.ChatMessage(session_id=session.id, role="assistant", content=reply))
    db.commit()

    return {"session_id": session.id, "reply": reply, "tool_calls": tool_calls}


@router.get("/history/{session_id}")
def history(session_id: int, db: Session = Depends(get_db),
            user: models.User = Depends(get_current_user)):
    # VULN A01/API1 (BOLA): no check that this session belongs to `user`.
    msgs = db.query(models.ChatMessage).filter(models.ChatMessage.session_id == session_id).all()
    return [{"role": m.role, "content": m.content, "created_at": m.created_at} for m in msgs]
