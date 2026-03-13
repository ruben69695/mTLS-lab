"""
client.py — mTLS HTTPS client
Presents a client certificate to the server, calls POST /todo, then GET /todo.
"""
import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SERVER_URL = "https://127.0.0.1:8443/todo"

CERTS_DIR   = Path(__file__).parent.parent / "certs"
CA_CERT     = CERTS_DIR / "ca.crt"
CLIENT_CERT = CERTS_DIR / "client.crt"
CLIENT_KEY  = CERTS_DIR / "client.key"


# ---------------------------------------------------------------------------
# SSL context
# ---------------------------------------------------------------------------
def build_ssl_context() -> ssl.SSLContext:
    """
    Build an SSLContext that:
      - Verifies the server certificate against our local CA (not the OS store)
      - Presents the client certificate + private key during the TLS handshake
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Verify server cert against our local CA only (not system trust store)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(cafile=str(CA_CERT))

    # Present our client certificate and key during the TLS handshake
    ctx.load_cert_chain(certfile=str(CLIENT_CERT), keyfile=str(CLIENT_KEY))

    # Enforce TLS 1.2 minimum
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    return ctx


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def build_opener() -> urllib.request.OpenerDirector:
    """Build an HTTPS opener using the mTLS SSL context."""
    ctx = build_ssl_context()
    handler = urllib.request.HTTPSHandler(context=ctx)
    return urllib.request.build_opener(handler)


def create_todo(task: str, done: bool = False) -> dict:
    """Perform authenticated POST /todo and return parsed JSON."""
    opener = build_opener()

    payload = json.dumps({
        "task": task,
        "done": done,
    }).encode("utf-8")

    request = urllib.request.Request(
        SERVER_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with opener.open(request, timeout=10) as response:
        raw = response.read()
        data = json.loads(raw)

    return data


def get_todos() -> dict:
    """Perform authenticated GET /todo and return parsed JSON."""
    opener = build_opener()

    with opener.open(SERVER_URL, timeout=10) as response:
        raw = response.read()
        data = json.loads(raw)

    return data


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    for path in (CA_CERT, CLIENT_CERT, CLIENT_KEY):
        if not path.exists():
            sys.exit(f"[ERROR] Missing file: {path}\n"
                     "Run 'bash certs/gen_certs.sh' first.")

    print(f"[CLIENT] Connecting to {SERVER_URL}")
    print(f"[CLIENT] Client cert: {CLIENT_CERT.name}")
    print(f"[CLIENT] CA trust:    {CA_CERT.name}\n")

    try:
        print("[CLIENT] Creating new TODO with POST /todo ...")
        created = create_todo("Put the cookies in the moon", True)

        print("[CLIENT] POST response (HTTP 201):\n")
        print(json.dumps(created, indent=2))
        print()

        print("[CLIENT] Fetching TODO list with GET /todo ...")
        data = get_todos()

    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        print(f"[CLIENT] HTTP error: {exc.code} {exc.reason}", file=sys.stderr)
        if error_body:
            print(error_body, file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(f"[CLIENT] Connection failed: {exc.reason}", file=sys.stderr)
        sys.exit(1)

    print(f"[CLIENT] Authenticated as: {data.get('client')!r}")
    print(f"[CLIENT] Response (HTTP 200):\n")
    print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()