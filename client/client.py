"""
client.py — mTLS HTTPS client
Presents a client certificate to the server and calls GET /todo.
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
# Request
# ---------------------------------------------------------------------------
def get_todos() -> dict:
    """Perform authenticated GET /todo and return parsed JSON."""
    ctx     = build_ssl_context()
    handler = urllib.request.HTTPSHandler(context=ctx)
    opener  = urllib.request.build_opener(handler)

    print(f"[CLIENT] Connecting to {SERVER_URL}")
    print(f"[CLIENT] Client cert: {CLIENT_CERT.name}")
    print(f"[CLIENT] CA trust:    {CA_CERT.name}\n")

    with opener.open(SERVER_URL, timeout=10) as response:
        raw  = response.read()
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

    try:
        data = get_todos()
    except urllib.error.URLError as exc:
        print(f"[CLIENT] Connection failed: {exc.reason}", file=sys.stderr)
        sys.exit(1)

    print(f"[CLIENT] Authenticated as: {data.get('client')!r}")
    print(f"[CLIENT] Response (HTTP 200):\n")
    print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
