# mTLS Local Lab — Python

A self-contained lab for understanding and testing **mutual TLS (mTLS)** using only Python's standard library and OpenSSL. No external certificate authorities, no cloud services — everything runs on `localhost`.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Folder Structure](#2-folder-structure)
3. [Certificate Creation](#3-certificate-creation)
4. [Server Setup](#4-server-setup)
5. [Client Setup](#5-client-setup)
6. [Testing Scenarios](#6-testing-scenarios)
7. [Security Explanation](#7-security-explanation)

---

## 1. Prerequisites

### Python

- **Python 3.10+** (uses `ssl.TLSVersion` enum, introduced in 3.7; type union `dict | None` requires 3.10)
- No third-party packages required — uses `http.server`, `ssl`, `urllib.request` from the standard library only

Verify:

```bash
python3 --version  # must be >= 3.10
```

### OpenSSL

- **OpenSSL 1.1.1+** or **LibreSSL 3.3+** (macOS ships LibreSSL; either works)

Verify:

```bash
openssl version  # e.g. OpenSSL 3.x or LibreSSL 3.x
```

### Operating System

- **macOS** (tested on macOS 14+) or **Linux** (Ubuntu 22.04+, Fedora 38+)
- A POSIX shell (`bash` or `zsh`) for running the cert generation script

---

## 2. Folder Structure

```
mtls-lab/
├── certs/                  # All X.509 certificates, keys, and OpenSSL configs
│   ├── ca.cnf              # CA certificate configuration
│   ├── ca.crt              # CA self-signed certificate (trust anchor)
│   ├── ca.key              # CA private key  ← keep secret, never share
│   ├── ca.srl              # CA serial number file (auto-generated)
│   ├── server.cnf          # Server certificate configuration (includes SAN)
│   ├── server.crt          # Server certificate (signed by CA)
│   ├── server.key          # Server private key
│   ├── server.csr          # Server certificate signing request (intermediate)
│   ├── client.cnf          # Client certificate configuration
│   ├── client.crt          # Client certificate (signed by CA)
│   ├── client.key          # Client private key
│   ├── client.csr          # Client CSR (intermediate)
│   └── gen_certs.sh        # Script that generates all of the above
├── server/
│   └── server.py           # mTLS HTTPS server (GET /todo)
└── client/
    ├── client.py           # mTLS HTTPS client (with client cert)
    └── client_no_cert.py   # Negative test — connection without client cert
```

> **Security note:** In a real environment, private keys (`*.key`) must never be committed to version control. Add `certs/*.key` to `.gitignore`.

---

## 3. Certificate Creation

### Why SAN and EKU are mandatory

| Extension | Purpose | What breaks without it |
|-----------|---------|------------------------|
| **SAN** (Subject Alternative Name) | Binds the certificate to hostnames/IPs the server actually runs on | Modern TLS stacks (Python `ssl`, Go, Chrome) reject certs without SAN even if CN matches |
| **EKU serverAuth** | Signals that the cert may be used to authenticate a server | Python's `ssl` module will reject a server cert without this OID |
| **EKU clientAuth** | Signals that the cert may be used to authenticate a client | Servers enforcing mTLS will reject a client cert without this OID |

### Step 0 — Use the provided script (recommended)

```bash
# From the project root
bash certs/gen_certs.sh
```

The script runs all 6 steps below in sequence and verifies the certificate chains at the end.

---

### Step 1 — Create the CA private key

```bash
openssl genrsa -out certs/ca.key 4096
```

- Generates a 4096-bit RSA key (larger than server/client keys — the CA is the root of trust)
- In production, protect this key with a passphrase (`-aes256`) and store it offline

---

### Step 2 — Create the self-signed CA certificate

```bash
openssl req \
  -new -x509 \
  -days 3650 \
  -key  certs/ca.key \
  -out  certs/ca.crt \
  -config certs/ca.cnf
```

- `-x509` skips the CSR step and self-signs directly — appropriate only for a root CA
- `basicConstraints = CA:true` marks this as a CA certificate; without it, browsers and TLS stacks will refuse to use it as a trust anchor
- 3650 days (≈10 years) is reasonable for a lab CA; production CAs should have shorter validity

---

### Step 3 — Create the server key and CSR

```bash
openssl genrsa -out certs/server.key 2048
openssl req \
  -new \
  -key    certs/server.key \
  -out    certs/server.csr \
  -config certs/server.cnf
```

The `server.cnf` file embeds the SAN via `req_extensions`:

```ini
[ req_ext ]
subjectAltName   = @alt_names
extendedKeyUsage = serverAuth

[ alt_names ]
DNS.1 = localhost
IP.1  = 127.0.0.1
```

---

### Step 4 — Sign the server certificate

```bash
openssl x509 \
  -req \
  -days 365 \
  -in   certs/server.csr \
  -CA   certs/ca.crt \
  -CAkey certs/ca.key \
  -CAcreateserial \
  -out  certs/server.crt \
  -extensions v3_server \
  -extfile certs/server.cnf
```

> **Critical:** The `-extensions v3_server -extfile certs/server.cnf` flags copy the SAN and EKU extensions from the config into the **signed** certificate. Without these flags, the extensions stay in the CSR only and are **not** included in the final cert.

---

### Step 5 — Create the client key and CSR

```bash
openssl genrsa -out certs/client.key 2048
openssl req \
  -new \
  -key    certs/client.key \
  -out    certs/client.csr \
  -config certs/client.cnf
```

The `client.cnf` requires only `clientAuth` (no SAN needed — clients are identified by CN, not by hostname):

```ini
[ req_ext ]
extendedKeyUsage = clientAuth
```

---

### Step 6 — Sign the client certificate

```bash
openssl x509 \
  -req \
  -days 365 \
  -in   certs/client.csr \
  -CA   certs/ca.crt \
  -CAkey certs/ca.key \
  -CAcreateserial \
  -out  certs/client.crt \
  -extensions v3_client \
  -extfile certs/client.cnf
```

---

### Verifying the certificates

```bash
# Inspect the server cert — look for SAN and EKU sections
openssl x509 -text -noout -in certs/server.crt

# Key fields to verify in the output:
#   X509v3 Subject Alternative Name:
#       DNS:localhost, IP Address:127.0.0.1
#   X509v3 Extended Key Usage:
#       TLS Web Server Authentication

# Inspect the client cert
openssl x509 -text -noout -in certs/client.crt

# Key fields to verify:
#   X509v3 Extended Key Usage:
#       TLS Web Client Authentication

# Verify certificate chains
openssl verify -CAfile certs/ca.crt certs/server.crt
# => certs/server.crt: OK

openssl verify -CAfile certs/ca.crt certs/client.crt
# => certs/client.crt: OK
```

---

## 4. Server Setup

### Dependencies

No external packages are required. The server uses only the Python standard library:

```
http.server  — BaseHTTPRequestHandler, HTTPServer
ssl          — SSLContext, CERT_REQUIRED, TLSVersion
json         — response serialization
pathlib      — certificate path resolution
```

### How the SSL context works

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

# ① Require client certificate — this is the "mutual" in mTLS
ctx.verify_mode = ssl.CERT_REQUIRED

# ② Load the CA that signed the client cert — only certs from this CA are accepted
ctx.load_verify_locations(cafile="certs/ca.crt")

# ③ Load server's own cert + key — sent to the client during the handshake
ctx.load_cert_chain(certfile="certs/server.crt", keyfile="certs/server.key")

# ④ Reject TLS 1.0 and 1.1 (deprecated per RFC 8996)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
```

| Flag | Effect |
|------|--------|
| `CERT_REQUIRED` | Server **demands** a client certificate; handshake fails if none is provided |
| `CERT_OPTIONAL` | Server accepts but does not require a client cert |
| `CERT_NONE` | Server ignores client certificates entirely (standard one-way TLS) |

### Reading the client certificate on the server

After the handshake, `self.connection.getpeercert()` returns a dictionary with the client's certificate fields:

```python
cert = self.connection.getpeercert()
# Example:
# {
#   'subject': ((('commonName', 'mtls-client'),),),
#   'issuer':  ((('commonName', 'mTLS Lab Root CA'),),),
#   'notAfter': 'Feb 25 00:00:00 2026 GMT',
#   ...
# }
```

### Running the server

```bash
python3 server/server.py
```

Expected output:

```
[SERVER] mTLS server listening on https://127.0.0.1:8443
[SERVER] Requiring client cert signed by: ca.crt
[SERVER] Press Ctrl+C to stop.
```

---

## 5. Client Setup

### Dependencies

No external packages required. Uses `urllib.request` with a custom `HTTPSHandler`.

### How the SSL context works

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

# ① Verify server cert against our local CA (not the OS trust store)
ctx.verify_mode   = ssl.CERT_REQUIRED
ctx.check_hostname = True
ctx.load_verify_locations(cafile="certs/ca.crt")

# ② Present client cert + key during the TLS handshake
ctx.load_cert_chain(certfile="certs/client.crt", keyfile="certs/client.key")
```

The custom context is injected into `urllib.request` via:

```python
handler = urllib.request.HTTPSHandler(context=ctx)
opener  = urllib.request.build_opener(handler)
opener.open(url)
```

### Running the client

Open a **second terminal** (server must be running):

```bash
python3 client/client.py
```

---

## 6. Testing Scenarios

### ✅ Successful mTLS call

**Terminal 1 — Start the server:**

```bash
python3 server/server.py
```

**Terminal 2 — Run the client:**

```bash
python3 client/client.py
```

**Expected client output:**

```
[CLIENT] Connecting to https://127.0.0.1:8443/todo
[CLIENT] Client cert: client.crt
[CLIENT] CA trust:    ca.crt

[CLIENT] Authenticated as: 'mtls-client'
[CLIENT] Response (HTTP 200):

{
  "client": "mtls-client",
  "todos": [
    {"id": 1, "task": "Set up local CA",          "done": true},
    {"id": 2, "task": "Issue server certificate", "done": true},
    {"id": 3, "task": "Issue client certificate", "done": true},
    {"id": 4, "task": "Configure mTLS server",    "done": true},
    {"id": 5, "task": "Validate mutual auth",     "done": false}
  ]
}
```

**Expected server output (stderr):**

```
[SERVER] 127.0.0.1 (cert CN='mtls-client') "GET /todo HTTP/1.1" 200 -
[SERVER] Authenticated client CN: 'mtls-client'
```

---

### ❌ Failure without client certificate

**Terminal 2 — Run the negative test:**

```bash
python3 client/client_no_cert.py
```

**Expected client output:**

```
[NEGATIVE TEST] Attempting connection WITHOUT client certificate...
[NEGATIVE TEST] Target: https://127.0.0.1:8443/todo

[NEGATIVE TEST] Connection rejected as expected.
[NEGATIVE TEST] Error: [SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED] tlsv13 alert certificate required (_ssl.c:...)

[NEGATIVE TEST] PASS: Server correctly refused unauthenticated client.
```

**Why it fails:**

The server's `ssl.CERT_REQUIRED` setting instructs OpenSSL to send a `CertificateRequest` message during the TLS handshake (in the `ServerHello` phase). When the client responds with an empty `Certificate` message (no cert), the server sends a TLS alert — either:

- `certificate_required` (TLS 1.3, RFC 8446 §6.2)
- `handshake_failure` (TLS 1.2)

The TCP connection is torn down before any HTTP data is exchanged. The `GET /todo` request is **never sent**.

**Verifying via OpenSSL s_client (alternative negative test):**

```bash
# Without client cert — should fail
openssl s_client \
  -connect 127.0.0.1:8443 \
  -CAfile certs/ca.crt

# With client cert — should succeed
openssl s_client \
  -connect 127.0.0.1:8443 \
  -CAfile  certs/ca.crt \
  -cert    certs/client.crt \
  -key     certs/client.key
```

---

## 7. Security Explanation

### The TLS 1.3 handshake with mutual authentication

```
Client                                    Server
  |                                          |
  |──── ClientHello (supported ciphers) ────>|
  |                                          |
  |<─── ServerHello ─────────────────────────|
  |<─── Certificate (server cert) ───────────|
  |<─── CertificateRequest ──────────────────|  ← mTLS only
  |<─── ServerHelloDone ─────────────────────|
  |                                          |
  |──── Certificate (client cert) ──────────>|  ← mTLS only
  |──── CertificateVerify (signed proof) ───>|  ← mTLS only
  |──── Finished ────────────────────────────>|
  |                                          |
  |<─── Finished ────────────────────────────|
  |                                          |
  |==== Encrypted application data ==========|  ← GET /todo
```

**Where client authentication occurs:** Between `CertificateRequest` and `Finished`. The client signs a digest of the handshake transcript using its private key (`CertificateVerify`). The server verifies the signature against the public key in the client certificate, then verifies the certificate chain back to the trusted CA.

**Why private keys never leave their side:**

The private key is used only to sign (`CertificateVerify`). The signature can be verified by anyone with the corresponding public key (embedded in the certificate), but the private key itself is never transmitted. This is the asymmetry that makes public-key cryptography secure.

### Common mistakes in mTLS setups

| Mistake | Consequence | Fix |
|---------|-------------|-----|
| Missing SAN in server cert | Python `ssl` raises `ssl.CertificateError: hostname mismatch` | Add `subjectAltName` to server cert config |
| Missing `clientAuth` EKU in client cert | Server rejects cert during handshake | Add `extendedKeyUsage = clientAuth` to client cert config |
| SAN in CSR but not in signed cert | Extensions silently dropped | Always pass `-extensions … -extfile …` to `openssl x509 -req` |
| `CERT_OPTIONAL` instead of `CERT_REQUIRED` | Clients can connect without any certificate | Use `CERT_REQUIRED` on the server |
| Using system CA store for client verification | Client accepts **any** CA-signed server cert | Explicitly `load_verify_locations(cafile=…)` with your CA only |
| Committing private keys to git | Key compromise | Add `certs/*.key` to `.gitignore` |
| Sharing one cert between all clients | Cannot revoke individual clients | Issue one certificate per client identity |
| Not checking `getpeercert()` fields | Any cert from the trusted CA is accepted | Validate CN, OU, or SAN fields to enforce authorization, not just authentication |

### Authentication vs. Authorization

mTLS provides **authentication** (who are you?) — it proves the client holds the private key for a certificate signed by the trusted CA. It does **not** automatically provide **authorization** (what are you allowed to do?). In production, always check the certificate subject fields after the handshake to enforce access control at the application layer.
# mTLS-lab
