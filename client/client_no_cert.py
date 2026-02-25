"""
client_no_cert.py — Negative test: attempt connection WITHOUT a client certificate.
Expected result: SSLError / connection refused by the server.
"""
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

SERVER_URL = "https://127.0.0.1:8443/todo"
CERTS_DIR  = Path(__file__).parent.parent / "certs"
CA_CERT    = CERTS_DIR / "ca.crt"


def build_ssl_context_no_client_cert() -> ssl.SSLContext:
    """Context that verifies the server but does NOT present a client certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode  = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(cafile=str(CA_CERT))
    # Intentionally NOT calling ctx.load_cert_chain() — no client cert
    return ctx


def main():
    print("[NEGATIVE TEST] Attempting connection WITHOUT client certificate...")
    print(f"[NEGATIVE TEST] Target: {SERVER_URL}\n")

    ctx     = build_ssl_context_no_client_cert()
    handler = urllib.request.HTTPSHandler(context=ctx)
    opener  = urllib.request.build_opener(handler)

    try:
        with opener.open(SERVER_URL, timeout=10) as response:
            print(f"[NEGATIVE TEST] UNEXPECTED SUCCESS — HTTP {response.status}")
            print("[NEGATIVE TEST] FAIL: Server accepted connection without client cert!")
            sys.exit(2)
    except urllib.error.URLError as exc:
        reason = exc.reason
        print(f"[NEGATIVE TEST] Connection rejected as expected.")
        print(f"[NEGATIVE TEST] Error: {reason}")
        print("\n[NEGATIVE TEST] PASS: Server correctly refused unauthenticated client.")
    except ssl.SSLError as exc:
        print(f"[NEGATIVE TEST] SSL handshake failed as expected: {exc}")
        print("\n[NEGATIVE TEST] PASS: mTLS enforcement is working correctly.")


if __name__ == "__main__":
    main()
