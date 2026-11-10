from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from .database import init_db
from .routers import auth_router, users_router, records_router, pharmacy_router
from .routers import messages_router, wearable_router, admin_router, chatbot_router

app = FastAPI(
    title="MEDIVULN-X API",
    version="2.0.0",
    description="Telehealth & personal health record platform - INTENTIONALLY "
                 "VULNERABLE for pentest training purposes. See VULNS.md.",
)


class VulnerableCORSMiddleware(BaseHTTPMiddleware):
    """
    VULN A05 (Security Misconfiguration): reflects ANY Origin header back
    as Access-Control-Allow-Origin, and allows credentials. This lets an
    attacker-controlled page at https://evil.com make authenticated requests
    to the API on behalf of a logged-in victim (cross-origin cookie/token theft).
    Unlike allow_origins=["*"], this pattern actually works with credentials.
    """
    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get("origin", "")
        if request.method == "OPTIONS":
            resp = Response(status_code=204)
        else:
            resp = await call_next(request)
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Access-Control-Allow-Methods"] = "*"
            resp.headers["Access-Control-Allow-Headers"] = "*"
            resp.headers["Vary"] = "Origin"
        return resp

app.add_middleware(VulnerableCORSMiddleware)

# VULN A05: no global rate limiting middleware anywhere in this app
# (API4 Unrestricted Resource Consumption applies to /auth/login,
# /chatbot/chat, and /records/fetch-from-url in particular).

app.include_router(auth_router.router)
app.include_router(users_router.router)
app.include_router(records_router.router)
app.include_router(pharmacy_router.router)
app.include_router(messages_router.router)
app.include_router(wearable_router.router)
app.include_router(admin_router.router)
app.include_router(chatbot_router.router)

import os
uploads_path = os.path.join(os.path.dirname(__file__), "..", "uploads")
os.makedirs(uploads_path, exist_ok=True)
# VULN A05: uploaded files served statically with no auth check on who can
# GET them, and no content-type sniffing protection - stored XSS via a
# crafted "lab report" HTML/SVG upload is possible.
app.mount("/uploads", StaticFiles(directory=uploads_path), name="uploads")


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/api/v2/health")
def health():
    return {"status": "ok", "service": "medivuln-x-api", "version": "2.0.0"}
