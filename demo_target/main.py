"""
Minimal Deliberately-Vulnerable Demo Target (Port 5000).

Serves ownership verification proof via:
1. Root homepage HTML <meta name="ethiosec-verification" content="..."> tag
2. Plain text challenge file at /.well-known/ethiosec-challenge.txt
"""

import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pydantic import BaseModel

app = FastAPI(title="EthioSec Demo Target", version="1.0.0")


@app.middleware("http")
async def expose_deliberate_demo_headers(request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Server"] = "EthioSecDemo/1.0"
    response.headers["X-Powered-By"] = "EthioSecDemo/1.0"
    return response

# In-memory token storage (defaults from environment variable DEMO_VERIFY_TOKEN)
CURRENT_TOKEN = os.environ.get("DEMO_VERIFY_TOKEN", "ethiosec-demo-initial-token-12345")


class TokenPayload(BaseModel):
    token: str


@app.get("/", response_class=HTMLResponse)
def index(response: Response):
    """Serves verification proof and a deliberately insecure demo cookie."""
    response.set_cookie(
        key="demo_session",
        value="demo-cookie-value",
        secure=False,
        httponly=False,
        samesite=None,
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>EthioSec Demo Target</title>
    <meta name="ethiosec-verification" content="{CURRENT_TOKEN}">
</head>
<body>
    <h1>EthioSec Scanner - Deliberately Vulnerable Demo Target</h1>
    <p>Target verification token: <code>{CURRENT_TOKEN}</code></p>
</body>
</html>
"""


@app.options("/")
def options_root():
    return Response(
        status_code=200,
        headers={"Allow": "GET, HEAD, OPTIONS, PUT, DELETE, TRACE"},
    )


@app.api_route("/", methods=["TRACE"], response_class=PlainTextResponse)
def trace_root():
    return "TRACE accepted by the deliberately vulnerable demo target."


@app.get("/error", response_class=PlainTextResponse)
def verbose_error():
    return PlainTextResponse(
        "Traceback (most recent call last):\n"
        "  File \"/srv/demo_target/main.py\", line 99, in vulnerable_handler\n"
        "    raise RuntimeError('demo stack trace')\n"
        "RuntimeError: demo stack trace",
        status_code=500,
    )


@app.get("/.well-known/ethiosec-challenge.txt", response_class=PlainTextResponse)
def challenge_file():
    """Serves plain text verification token."""
    return CURRENT_TOKEN


@app.post("/set-token")
def set_token(payload: TokenPayload):
    """Dynamically set the verification token for live manual testing."""
    global CURRENT_TOKEN
    CURRENT_TOKEN = payload.token.strip()
    return {"status": "updated", "token": CURRENT_TOKEN}


@app.get("/token")
def get_token():
    """Inspect current active verification token."""
    return {"token": CURRENT_TOKEN}
