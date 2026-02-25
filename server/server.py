"""
server.py — mTLS-enforced HTTPS server
Serves GET /todo and requires a valid client certificate signed by the local CA.
"""
import datetime
import hashlib
import json
import logging
import ssl
import sys
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HOST = "127.0.0.1"
PORT = 8443

CERTS_DIR = Path(__file__).parent.parent / "certs"
CA_CERT    = CERTS_DIR / "ca.crt"
SERVER_CERT = CERTS_DIR / "server.crt"
SERVER_KEY  = CERTS_DIR / "server.key"

TODO_ITEMS = [
    {"id": 1, "task": "Set up local CA",             "done": True},
    {"id": 2, "task": "Issue server certificate",    "done": True},
    {"id": 3, "task": "Issue client certificate",    "done": True},
    {"id": 4, "task": "Configure mTLS server",       "done": True},
    {"id": 5, "task": "Validate mutual auth",        "done": False},
]

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.DEBUG,
                    format="[SERVER] %(levelname)s %(message)s",
                    stream=sys.stderr)
log = logging.getLogger("mtls.server")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
_OID_SHORT = {
    "commonName":             "CN",
    "organizationName":       "O",
    "organizationalUnitName": "OU",
    "countryName":            "C",
    "stateOrProvinceName":    "ST",
    "localityName":           "L",
}


def _format_cert_subject(cert_field):
    """Flatten getpeercert()-style subject/issuer tuples to 'CN=foo, O=bar'."""
    parts = []
    for rdn in cert_field:
        for oid, val in rdn:
            parts.append(f"{_OID_SHORT.get(oid, oid)}={val}")
    return ", ".join(parts)


def _cert_validity_status(nb, na):
    """Return a human-readable validity string for a certificate."""
    fmt = "%b %d %H:%M:%S %Y %Z"
    try:
        not_before = datetime.datetime.strptime(nb, fmt).replace(tzinfo=datetime.timezone.utc)
        not_after  = datetime.datetime.strptime(na, fmt).replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        if now < not_before:
            return f"NOT YET VALID (from {not_before.date()})"
        if now > not_after:
            return f"EXPIRED (expired {not_after.date()})"
        days = (not_after - now).days
        return f"VALID (expires {not_after.date()}, {days} days remaining)"
    except Exception as exc:
        return f"UNKNOWN ({exc})"


def _cert_fingerprint(der_bytes):
    """Return a SHA-256 fingerprint as colon-separated uppercase hex."""
    d = hashlib.sha256(der_bytes).hexdigest().upper()
    return ":".join(d[i:i+2] for i in range(0, len(d), 2))


def _parse_cert_file(path):
    """
    Parse a PEM cert file using the private-but-stable
    ssl._ssl._test_decode_cert (used by ssl's own test suite).
    Returns an empty dict if unavailable.
    """
    try:
        return ssl._ssl._test_decode_cert(str(path))
    except Exception:
        return {}


def _extract_cn(cert: dict | None) -> str:
    """Return the CN value from a parsed peer certificate dict, or 'unknown'."""
    if not cert:
        return "unknown"
    for field in cert.get("subject", []):
        for key, value in field:
            if key == "commonName":
                return value
    return "unknown"


def _print_cert_info(label, cert_path):
    """Print certificate details to stdout during startup."""
    cert = _parse_cert_file(cert_path)
    if not cert:
        print(f"  {label}: (could not parse {cert_path.name})")
        return
    subject  = _format_cert_subject(cert.get("subject", ()))
    issuer   = _format_cert_subject(cert.get("issuer",  ()))
    serial   = cert.get("serialNumber", "unknown")
    validity = _cert_validity_status(
        cert.get("notBefore", ""), cert.get("notAfter", ""))
    sans     = cert.get("subjectAltName", ())
    san_str  = ", ".join(f"{t}:{v}" for t, v in sans) if sans else "(none)"

    # Fingerprint from raw DER bytes when available
    fp = "(unavailable)"
    try:
        der = ssl.PEM_cert_to_DER_cert(cert_path.read_text())
        fp  = _cert_fingerprint(der)
    except Exception:
        pass

    print(f"  {label}:")
    print(f"    Subject  : {subject}")
    print(f"    Issuer   : {issuer}")
    print(f"    Serial   : {serial}")
    print(f"    Validity : {validity}")
    print(f"    SAN      : {san_str}")
    print(f"    SHA-256  : {fp}")


def log_startup_diagnostics(ctx: ssl.SSLContext):
    """Print startup diagnostics to stdout: cert details, TLS config, cipher list."""
    print("=" * 72)
    print("mTLS Server — Startup Diagnostics")
    print("=" * 72)

    # --- Certificate files ---
    print("\n[Certificate Paths]")
    print(f"  CA cert    : {CA_CERT}")
    print(f"  Server cert: {SERVER_CERT}")
    print(f"  Server key : {SERVER_KEY}")

    # --- TLS context settings ---
    print("\n[TLS Context]")
    min_ver = getattr(ctx.minimum_version, "name", str(ctx.minimum_version))
    max_ver = getattr(ctx.maximum_version, "name", str(ctx.maximum_version))
    verify  = ctx.verify_mode.name if hasattr(ctx.verify_mode, "name") else str(ctx.verify_mode)
    no_reneg = bool(ctx.options & ssl.OP_NO_RENEGOTIATION)
    print(f"  Min version      : {min_ver}")
    print(f"  Max version      : {max_ver}")
    print(f"  Verify mode      : {verify}")
    print(f"  No renegotiation : {no_reneg}")

    # --- Cipher list ---
    print("\n[Cipher List]")
    ciphers = ctx.get_ciphers()
    if ciphers:
        for c in ciphers:
            name     = c.get("name", "?")
            protocol = c.get("protocol", "?")
            bits     = c.get("strength_bits", "?")
            print(f"  {name:<45} {protocol:<8} {bits}-bit")
    else:
        print("  (no cipher info available)")

    # --- Certificate details ---
    print("\n[Server Certificate]")
    _print_cert_info("server.crt", SERVER_CERT)

    print("\n[CA Certificate]")
    _print_cert_info("ca.crt", CA_CERT)

    print("=" * 72)
    print()


# ---------------------------------------------------------------------------
# Server subclass — intercepts TLS handshake errors
# ---------------------------------------------------------------------------
class MTLSServer(HTTPServer):
    """
    HTTPServer subclass that logs TLS handshake failures.

    HTTPServer._handle_request_noblock() catches OSError (the parent of
    ssl.SSLError) silently before handle_error() is called, so get_request()
    is the only reliable place to intercept handshake failures.
    """

    def get_request(self):
        try:
            return super().get_request()
        except ssl.SSLError as exc:
            reason  = getattr(exc, "reason",  None) or exc.strerror or str(exc)
            library = getattr(exc, "library", None)
            lib_str = f" [{library}]" if library else ""
            log.error("TLS HANDSHAKE FAILED%s — %s | raw: %s",
                      lib_str, reason, exc)
            raise  # re-raise so caller's 'except OSError: return' still fires
        except (ConnectionResetError, BrokenPipeError) as exc:
            log.warning("CONNECTION ERROR during accept: %s", exc)
            raise

    def handle_error(self, request, client_address):
        """Called for errors AFTER a successful handshake (HTTP processing errors)."""
        peer = f"{client_address[0]}:{client_address[1]}"
        _, exc_val, _ = sys.exc_info()
        if isinstance(exc_val, (ConnectionResetError, BrokenPipeError)):
            log.warning("CONNECTION RESET by %s", peer)
        elif isinstance(exc_val, ssl.SSLError):
            log.error("SSL ERROR from %s after handshake — %s",
                      peer, getattr(exc_val, "reason", exc_val))
        else:
            log.error("UNEXPECTED ERROR from %s\n%s",
                      peer, traceback.format_exc().rstrip())


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------
class MTLSHandler(BaseHTTPRequestHandler):
    """Handles incoming HTTPS requests after mTLS handshake succeeds."""

    # ------------------------------------------------------------------
    # Connection-level hooks
    # ------------------------------------------------------------------
    def handle(self):
        """Called once per accepted connection, after handshake completes."""
        self._log_handshake_info()
        super().handle()

    def _log_handshake_info(self):
        """Log negotiated TLS version + cipher suite."""
        version    = self.connection.version() or "unknown"
        cipher     = self.connection.cipher()
        cipher_str = (f"{cipher[0]} ({cipher[1]}, {cipher[2]}-bit)"
                      if cipher else "unknown")
        log.info("TLS HANDSHAKE OK | peer=%s | version=%s | cipher=%s",
                 self.address_string(), version, cipher_str)
        self._log_client_cert()

    def _log_client_cert(self):
        """Log full details of the peer certificate."""
        cert = self.connection.getpeercert()
        if not cert:
            log.warning("CLIENT CERT: no cert (unexpected with CERT_REQUIRED)")
            return
        subject  = _format_cert_subject(cert.get("subject", ()))
        issuer   = _format_cert_subject(cert.get("issuer",  ()))
        serial   = cert.get("serialNumber", "unknown")
        validity = _cert_validity_status(
            cert.get("notBefore", ""), cert.get("notAfter", ""))
        sans     = cert.get("subjectAltName", ())
        san_str  = ", ".join(f"{t}:{v}" for t, v in sans) if sans else "(none)"
        log.info(
            "CLIENT CERT | subject=%s | issuer=%s | serial=%s | validity=%s | SAN=%s",
            subject, issuer, serial, validity, san_str,
        )

    def _log_request_headers(self):
        """Log all HTTP request headers at DEBUG level."""
        log.debug("REQUEST HEADERS | %s %s %s",
                  self.command, self.path, self.request_version)
        for h in self.headers:
            log.debug("  %s: %s", h, self.headers[h])

    # ------------------------------------------------------------------
    # Standard logging override
    # ------------------------------------------------------------------
    def log_message(self, fmt, *args):
        client_cert = self.connection.getpeercert()
        subject     = _extract_cn(client_cert)
        log.info("REQUEST | peer=%s | cert-CN=%r | %s",
                 self.address_string(), subject, fmt % args)

    # ------------------------------------------------------------------
    # Request handlers
    # ------------------------------------------------------------------
    def do_GET(self):
        self._log_request_headers()
        if self.path == "/todo":
            self._handle_todo()
        else:
            self._send_json(404, {"error": f"Not found: {self.path}"})

    def _handle_todo(self):
        client_cert = self.connection.getpeercert()
        subject     = _extract_cn(client_cert)
        log.info("AUTHENTICATED | CN=%r | serving /todo", subject)
        self._send_json(200, {"client": subject, "todos": TODO_ITEMS})

    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# SSL context builder
# ---------------------------------------------------------------------------
def build_ssl_context() -> ssl.SSLContext:
    """
    Build an SSLContext that:
      - Requires a client certificate signed by our CA  (CERT_REQUIRED)
      - Loads the server certificate and private key
      - Restricts to TLS 1.2 and above
      - Disables insecure renegotiation
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Require client to present a cert (this is what makes it mTLS)
    ctx.verify_mode = ssl.CERT_REQUIRED

    # Load the CA that signed the client certificate
    ctx.load_verify_locations(cafile=str(CA_CERT))

    # Load server's own certificate and private key
    ctx.load_cert_chain(certfile=str(SERVER_CERT), keyfile=str(SERVER_KEY))

    # Enforce TLS 1.2 minimum; reject TLS 1.0 / 1.1
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Disable server-side session renegotiation (defence-in-depth)
    ctx.options |= ssl.OP_NO_RENEGOTIATION

    return ctx


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    for path in (CA_CERT, SERVER_CERT, SERVER_KEY):
        if not path.exists():
            sys.exit(f"[ERROR] Missing certificate file: {path}\n"
                     "Run 'bash certs/gen_certs.sh' first.")

    ctx    = build_ssl_context()
    server = MTLSServer((HOST, PORT), MTLSHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    log_startup_diagnostics(ctx)

    print(f"[SERVER] mTLS server listening on https://{HOST}:{PORT}")
    print(f"[SERVER] Requiring client cert signed by: {CA_CERT.name}")
    print("[SERVER] Press Ctrl+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down.")


if __name__ == "__main__":
    main()
