"""The token endpoint: one POST, TLS 1.3 on loopback, out-of-process.

`smoke/g4/DESIGN.md` SS 5.1 and SS 5.4. Deliberately small: **`POST /token` and
nothing else** -- no authorization endpoint, no introspection, no revocation, no
`.well-known` metadata, no `jwks_uri`. Every endpoint that does not exist is one
no test needs and one the design does not specify.

Implementation choices that carry a measurement bias are SS 8.2's, and are made
the way SS 8.2 decided: the signing key is parsed **once at start-up** and the
signer reused; the server speaks HTTP/1.1 with **keep-alive** so the connection
is reused across hops; state is in memory with no disk I/O on the request path;
the response is built once. Each of those, done the other way, would inflate the
B2 round trip and bias the overhead comparison **toward B3** -- toward our own
hypothesis, which is the direction that must never be taken carelessly.

Transport is **TLS 1.3** (OAuth 2.1 SS 1.5 MUST; its plain-`http` exception
covers loopback *redirect URIs* only, which this profile does not use). The
certificate is generated at run time from the sealed seed. Stdlib `ssl` can only
load a certificate chain from a file, so the TLS key is written to a private
temporary file and **deleted immediately** once the context holds it; that is
the TLS key, never the AS signing key, which never leaves memory (SS 5.4).
"""

import ipaddress
import json
import ssl
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from src.sut.dpop import NonceStore
from src.sut.oauth_as.config import ASConfig
from src.sut.oauth_as.errors import INVALID_REQUEST, OAuthError
from src.sut.oauth_as.exchange import exchange, parse_form
from src.sut.oauth_as.keys import SigningKey

MAX_BODY_BYTES = 64 * 1024


def build_tls_context(tls_key: Ed25519PrivateKey) -> tuple[ssl.SSLContext, bytes]:
    """A TLS 1.3 server context plus the certificate PEM callers must trust.

    Returns the PEM so the client can verify from memory (`cadata=`) without a
    certificate ever being installed anywhere.
    """
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            # The literal loopback address is included so clients can dial
            # 127.0.0.1 directly. Resolving the name `localhost` tries ::1 first
            # on a dual-stack host and waits for that connection to fail before
            # falling back, which adds most of a second to **every** exchange --
            # exactly the kind of gratuitous per-hop connection cost SS 8.2 rules
            # out because it inflates B2's measured round trip toward B3.
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(tls_key, None)
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = tls_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    directory = Path(tempfile.mkdtemp(prefix="aasc-as-tls-"))
    cert_file, key_file = directory / "cert.pem", directory / "key.pem"
    try:
        cert_file.write_bytes(cert_pem)
        key_file.write_bytes(key_pem)
        context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    finally:
        # The TLS key exists on disk only for the duration of this load.
        cert_file.unlink(missing_ok=True)
        key_file.unlink(missing_ok=True)
        directory.rmdir()
    return context, cert_pem


class TokenEndpoint(BaseHTTPRequestHandler):
    """`POST /token`. Anything else is 404; any other method is 405."""

    protocol_version = "HTTP/1.1"  # SS 8.2: keep-alive, connection reused across hops
    server_version = "aasc-experiment-as/1.0"
    sys_version = ""

    def do_POST(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler's naming
        if self.path.split("?")[0] != "/token":
            self._send_json(404, {"error": "not_found"})
            return
        try:
            response = self._handle_exchange()
        except OAuthError as error:
            self._send_json(error.status, error.body(), extra_headers=error.headers)
            return
        self._send_json(200, response.body(), extra_headers={"Cache-Control": "no-store"})

    def do_GET(self) -> None:  # noqa: N802
        # No discovery document, no jwks_uri, no introspection (SS 5.1).
        self._send_json(404, {"error": "not_found"})

    def _handle_exchange(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            raise OAuthError(INVALID_REQUEST, "malformed-request", "missing or oversized body")
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse_form(body)
        return exchange(
            form,
            config=self.server.as_config,
            signing_key=self.server.signing_key,
            client_credentials=self._client_credentials(form),
            used_authorization_header=self.headers.get("Authorization") is not None,
            dpop_proofs=self.headers.get_all("DPoP") or [],
            nonce_store=self.server.nonce_store,
        )

    def _client_credentials(self, form: dict) -> tuple[str, str] | None:
        """`client_secret_basic` (SS 5.1), with the form fallback OAuth 2.1 permits."""
        header = self.headers.get("Authorization")
        if header and header.lower().startswith("basic "):
            import base64
            from urllib.parse import unquote

            try:
                decoded = base64.b64decode(header[6:].strip()).decode("utf-8")
                client_id, _, secret = decoded.partition(":")
            except (ValueError, UnicodeDecodeError):
                return None
            return unquote(client_id), unquote(secret)
        if "client_id" in form and "client_secret" in form:
            return form["client_id"], form["client_secret"]
        return None

    def _send_json(self, status: int, payload: dict, extra_headers: dict | None = None) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args) -> None:  # noqa: D102 -- silence stderr access logging
        return


class AuthorizationServer(ThreadingHTTPServer):
    """The AS process's HTTP server, holding the one signing key."""

    daemon_threads = True

    def __init__(
        self,
        config: ASConfig,
        signing_key: SigningKey,
        tls_context: ssl.SSLContext,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        super().__init__((host, port), TokenEndpoint)
        self.as_config = config
        self.signing_key = signing_key  # parsed once, reused (SS 8.2)
        self.nonce_store = NonceStore("as")  # AS namespace, distinct from the RS's
        self.socket = tls_context.wrap_socket(self.socket, server_side=True)

    @property
    def port(self) -> int:
        return self.server_address[1]


def serve_in_thread(
    config: ASConfig, signing_key: SigningKey, tls_context: ssl.SSLContext
) -> tuple[AuthorizationServer, threading.Thread]:
    """Start the server on an ephemeral loopback port. Used by tests and by `__main__`."""
    server = AuthorizationServer(config, signing_key, tls_context)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
