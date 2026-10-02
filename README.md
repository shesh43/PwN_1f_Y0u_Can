# Aegis Health — Vulnerable Telehealth Platform

**Intentionally vulnerable web + API application for pentest training.**
Do not deploy on a public server or any network you don't fully control.

---

## What's inside

A realistic telehealth SaaS with:
- Patient portal, doctor/pharmacist/admin roles
- Health records API with file upload and URL import
- Prescription & pharmacy refill flow
- Doctor-patient messaging
- Wearable device webhook ingestion
- AI symptom-checker chatbot (RAG + tool-calling)
- Auto-generated Swagger docs at `/docs`
- Minimal web frontend (plain HTML/JS) at `frontend/`

**Coverage:** all OWASP Web Top 10 (2021), all OWASP API Top 10 (2023), and
two LLM Top 10 findings (LLM01 prompt injection + LLM06 excessive agency).
Full answer key in `VULNS.md` — read AFTER you've pentested, not before.

---

## Setup

**Requirements:** Python 3.10+ on Linux/macOS (Windows with WSL works too).

```bash
# 1. Clone / unzip the project, then:
cd aegis-health

# 2. Create virtualenv and install deps
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r backend/requirements.txt
pip install "bcrypt==4.0.1"       # pin for passlib compat

# 3. Seed the database with demo users
cd backend
python seed.py
cd ..
```

---

## Running

**Terminal 1 — API server:**
```bash
source venv/bin/activate
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 — Frontend (static file server):**
```bash
cd frontend
python3 -m http.server 3000
```

Open:
- Web app  → http://localhost:3000
- API docs → http://localhost:8000/docs
- API raw  → http://localhost:8000/api/v2/health

---

## Demo accounts

| Role | Email | Password |
|---|---|---|
| patient | alice.patient@aegishealthcorp.com | Patient123! |
| patient | bob.patient@aegishealthcorp.com | Patient123! |
| doctor | dr.chen@aegishealthcorp.com | Doctor123! |
| pharmacist | pharm.rao@aegishealthcorp.com | Pharm123! |
| admin | admin@aegishealthcorp.com | Admin123! |

---

## Recommended pentest tools

- **Burp Suite Community** — intercept and replay all web + API traffic
- **Postman or curl** — direct API testing against Swagger spec
- **jwt.io** — inspect and forge JWT tokens
- **Python requests** — scripted attack chains

**Tip:** open Swagger at `/docs`, log in via `/api/v2/auth/login`, paste
the access token into the Authorize button at the top right, then explore
every endpoint. Most BOLA/auth findings are discoverable just from the
Swagger surface — increment object IDs, try endpoints cross-user, and
watch for missing ownership checks in the responses.

---

## Reset

Delete `backend/aegis.db` and re-run `python seed.py` from the `backend/` directory.
