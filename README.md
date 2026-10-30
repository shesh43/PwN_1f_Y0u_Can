# Aegis Health

A deliberately vulnerable telehealth platform built to practice and demonstrate real-world web, API, and AI security assessment — end to end, from exploitation to remediation.

This is not a checklist app. Every vulnerability here was designed the way it actually happens in production systems: as a single missing check, a trust assumption that doesn't hold, or an architectural shortcut that works until someone looks for it. The goal is to practice finding *that kind* of bug, not to memorize a list of CVE names.

---

## Why this exists

Most vulnerable-by-design applications teach you to recognize a vulnerability class by its symptom — "this looks like SQL injection" or "this response looks like it leaked data." That's useful, but it's not how vulnerabilities get found in real systems. Real systems don't label their bugs.

Aegis Health is built the other way around: as a working application first, with vulnerabilities that exist *because of how the code is actually written*, not because a label says "vulnerable here." Every finding has a root cause you can point to in the source, a reason the developer's assumption failed, and a fix that addresses that specific failure — not a generic "add validation" note.

The application also intentionally covers a category most vulnerable-app projects skip entirely: AI-specific vulnerabilities. Aegis Health includes an AI symptom-checker with a retrieval-augmented generation (RAG) pipeline and tool-calling, deliberately built with the same kind of trust-boundary failure that causes prompt injection in production LLM systems. If you've only practiced OWASP Top 10 web vulnerabilities, this is the part of the application that will be unfamiliar — and it's the part most worth spending time on, because LLM-integrated applications are becoming the norm, not the exception.

---

## What you're testing

Aegis Health is a telehealth and personal health record platform with:

- **Patient portal** — registration, authentication, session management
- **Health records** — lab reports, imaging notes, clinical notes, with file upload and external URL import
- **Prescriptions and pharmacy** — viewing, requesting refills
- **Messaging** — patient-to-provider communication
- **AI symptom checker** — a chat-based assistant with access to the patient's records and a small set of callable tools
- **Wearable device ingestion** — a webhook endpoint that accepts health telemetry from connected devices
- **Administrative functions** — user management, audit logging

Four roles exist: patient, doctor, pharmacist, and admin. Understanding what each role *should* and *should not* be able to do is the starting point for almost every finding in this application — most of the vulnerabilities here are failures of that boundary, not failures of input validation.

---

## Getting started

### Requirements

- Python 3.10 or later
- No external services, no API keys, no cloud account — everything runs locally

### Setup

```bash
git clone <this-repo>
cd aegis-health

python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r backend/requirements.txt

cd backend
python seed.py
```

### Running it

**Terminal 1 — API server:**
```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — web frontend:**
```bash
cd frontend
python -m http.server 3000
```

Open `http://localhost:3000` for the patient portal, or `http://localhost:8000/docs` for the interactive API specification. The second one is where most of your testing will actually happen — the frontend exists to make the application feel real, but the API is the attack surface.

### Test accounts

| Role | Email | Password |
|---|---|---|
| Patient | alice.patient@aegishealthcorp.com | Patient123! |
| Patient | bob.patient@aegishealthcorp.com | Patient123! |
| Doctor | dr.chen@aegishealthcorp.com | Doctor123! |
| Pharmacist | pharm.rao@aegishealthcorp.com | Pharm123! |
| Admin | admin@aegishealthcorp.com | Admin123! |

Having two patient accounts (Alice and Bob) is deliberate — most of the access-control findings in this application only become visible when you have a second identity to test *against*. A single-account tester misses them entirely.

---

## How to approach this

The temptation with a vulnerable application is to open the findings file and reproduce each one mechanically. That will confirm the vulnerabilities exist, but it won't build the skill of finding them without being told where to look. A more useful approach:

**1. Map the application before touching it.** Open the API specification at `/docs` and read every endpoint. For each one, ask: what object does this touch, what role is this meant for, and what does the server need to verify before it should answer? Write this down. Most of the findings in this application are places where that verification is simply missing — you can predict several of them before sending a single request, just from reading the surface.

**2. Establish more than one identity.** Authentication findings are invisible from a single account. You need a second patient, at minimum, to test whether the boundary between "my data" and "someone else's data" is actually enforced or just assumed.

**3. Follow every object identifier.** Any endpoint that takes a numeric ID — a record, a prescription, a message thread — is a candidate for broken object-level access control. Request your own object, confirm it works, then change only the ID and see what comes back.

**4. Read the business logic, not just the authentication.** Some of the more interesting findings here have nothing to do with who you're logged in as. They're about what the *feature* is supposed to prevent — a refill limit, a quantity cap — and whether the server actually enforces it or just trusts the client to behave.

**5. Treat the AI assistant as a second application with its own attack surface.** It has its own authentication context, its own data access, and its own command surface — the chat message. Everything you'd test on a normal endpoint, test here too: what can this feature access, and does it verify that the request asking for it is actually authorized to have it.

**6. Write down the root cause, not just the symptom.** "This endpoint returns someone else's data" is a symptom. "This endpoint fetches the object by ID and returns it without comparing the object's owner to the authenticated user" is a root cause — and it's the version of the finding that tells you how to fix it and what else in the codebase might have the same problem.

---

## A note on the AI findings specifically

If most of your security background is in traditional web application testing, the prompt injection findings in this application will feel unfamiliar at first, and that's exactly why they're worth the extra time.

The core idea is this: the chatbot retrieves the patient's stored records to use as context, then combines that retrieved content with the user's message before deciding what to do. The failure is that nothing in the system distinguishes between "an instruction the authenticated user actually typed" and "text that happens to appear inside retrieved data." If an instruction-shaped string ends up inside a stored record — through any of the normal ways content gets into this application — it's treated identically to a live command from the user.

This matters more than it might first appear, because it means the attacker doesn't need access to the victim's session at all. They need access to something the victim's AI assistant will later retrieve. That's a fundamentally different threat model than almost everything else in this application, and it's the direction a growing share of real-world application security work is heading.

Spend real time here. Understand not just that the injection works, but *why* the architecture allows it — and what a fix would need to guarantee instead of merely checking for.

---

## Reporting what you find

Part of the value of this project is practicing the documentation side, not just the exploitation side. For each finding, aim to capture:

- **What the vulnerability actually is**, stated precisely — not "broken access control" in the abstract, but the specific missing check, in the specific endpoint, with the specific consequence
- **A reproducible proof of concept** — the exact request and response that demonstrates it, not a description of what you expect would happen
- **The realistic impact** — specific to this application and this data, not a generic severity label copied from a framework
- **A remediation that addresses the actual root cause** — if your fix is "add validation," you haven't yet identified what's actually missing

This repository includes a full findings reference once you're ready for it — but working through the application without it first is where the actual skill gets built. The reference is for checking your work afterward, not for finding the vulnerabilities in the first place.

---

## Scope and intent

This application is built for personal security research and education in an isolated local environment. It is intentionally insecure by design across authentication, authorization, business logic, infrastructure configuration, and AI-specific trust boundaries. It should never be deployed to a shared network, a public server, or any environment handling real data. No portion of this codebase — including its authentication scheme, its CORS configuration, or any pattern used in the AI pipeline — should be reused in a production system.

---

## Stack

FastAPI, SQLAlchemy, SQLite, and a dependency-free HTML/JavaScript frontend. No build step, no external services, nothing to configure beyond what's listed above. The simplicity is deliberate — the attack surface should be the point, not the deployment.
