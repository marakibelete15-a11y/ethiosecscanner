"""
Minimal Deliberately-Vulnerable Demo Target (Port 5000).

Serves ownership verification proof via:
1. Root homepage HTML <meta name="ethiosec-verification" content="..."> tag
2. Plain text challenge file at /.well-known/ethiosec-challenge.txt
"""

import os
from html import escape
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
POST_FORM_SUBMISSIONS = 0


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
    <nav>
        <a href="/product?id=1">Product</a>
        <a href="/search?q=demo">Search</a>
        <a href="/.env">Fake environment file</a>
        <a href="/.git/HEAD">Fake Git ref</a>
        <a href="/safe-search?q=demo">Safe search</a>
        <a href="/safe-product?id=1">Safe product</a>
    </nav>
    <form action="/search" method="get"><input name="q" value="demo"></form>
    <form action="/submit" method="post"><input name="comment" value="demo"></form>
</body>
</html>
"""


@app.get("/.env", response_class=PlainTextResponse)
def fake_env():
	return "DEMO_MODE=true\nFAKE_API_KEY=not-a-real-secret\nFAKE_DB_PASSWORD=example-only\n"


@app.get("/.git/HEAD", response_class=PlainTextResponse)
def fake_git_head():
	return "ref: refs/heads/demo\n"


@app.get("/product", response_class=PlainTextResponse)
def product(id: str = "1"):
	if "'" in id:
		return PlainTextResponse("SQLite3.OperationalError: unrecognized token near quote", status_code=500)
	return f"Demo product {id}"


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
	return f"<html><body><h1>Search results for: {q}</h1></body></html>"


@app.get("/safe-search", response_class=HTMLResponse)
def safe_search(q: str = ""):
	return f"<html><body><h1>Search results for: {escape(q, quote=True)}</h1></body></html>"


@app.get("/safe-product", response_class=PlainTextResponse)
def safe_product(id: str = "1"):
	return f"Demo product {escape(id, quote=True)}"


@app.post("/submit")
def submit_post_form():
	global POST_FORM_SUBMISSIONS
	POST_FORM_SUBMISSIONS += 1
	return {"submitted": True}


@app.get("/.well-known/security.txt", response_class=PlainTextResponse)
def security_txt():
	return "Contact: security@example.invalid\n"


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


@app.get("/{unmatched_path:path}", response_class=HTMLResponse)
def soft_not_found(unmatched_path: str):
	return HTMLResponse("<html><body><h1>page not found</h1></body></html>", status_code=200)
