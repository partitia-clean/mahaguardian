"""
mTLS certificate generation and connection management.

Security guarantees:
  - Self-signed CA — no external trust dependency.
  - All certs generated with the cryptography library (not openssl subprocess).
  - Guardian and agent both present certificates (mutual TLS).
  - Only Guardian's certificate is accepted by agents.
  - Agent certificate verified against CA on every connection.
  - No inbound ports opened on user device — Guardian initiates all connections.
"""
from __future__ import annotations

import os
import platform
import re
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.x509.oid import NameOID

import guardian.audit as audit
from shared.config import (
    AGENT_CERTS_DIR,
    CA_CERT_PATH,
    CA_KEY_PATH,
    CERTS_DIR,
    GUARDIAN_CERT_PATH,
    GUARDIAN_KEY_PATH,
)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_AGENT_ID_RE = re.compile(r'^[a-zA-Z0-9_-]+$')


def _validate_agent_id(agent_id: str) -> None:
    """
    Validate agent_id is safe for use in file paths and cert CNs.
    Raises ValueError if it contains path traversal or special characters.
    """
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError(
            f"Invalid agent_id '{agent_id}': must be "
            f"alphanumeric, hyphens, or underscores only."
        )


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def _set_owner_only(path: Path) -> None:
    """Set file permissions to 0o600. No-op on Windows."""
    if platform.system() != "Windows":
        os.chmod(path, 0o600)


def _passphrase_bytes(passphrase: str | bytes) -> bytes:
    """Encode passphrase to bytes if needed."""
    if isinstance(passphrase, str):
        return passphrase.encode("utf-8")
    return passphrase


def _write_pem(path: Path, data: bytes, *, private: bool = False) -> None:
    """
    Write PEM data to file.

    If *private* is True on Unix, the file is created with 0o600
    permissions atomically via os.open() — no window where another
    process can read the file before permissions are set.
    On Windows this falls back to a normal write (NTFS uses ACLs).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if private and platform.system() != "Windows":
        fd = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
    else:
        path.write_bytes(data)


# ---------------------------------------------------------------------------
# Peer identity verification (FIX A)
# ---------------------------------------------------------------------------

def verify_peer_agent_id_from_der(
    der_cert: bytes,
    expected_agent_id: str,
) -> bool:
    """
    Verify that a DER-encoded certificate's CN matches the expected agent_id.
    Raises ValueError if mismatch or missing CN.

    Used by the peer cert middleware and bootstrap endpoints where
    the cert has already been extracted from the TLS session.
    """
    cert = x509.load_der_x509_certificate(der_cert)
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs:
        raise ValueError("Peer certificate has no CN attribute.")
    cn = cn_attrs[0].value
    if cn != expected_agent_id:
        raise ValueError(
            f"Cert CN '{cn}' does not match "
            f"expected agent_id '{expected_agent_id}'"
        )
    return True


def verify_peer_agent_id(
    ssl_socket: object,
    expected_agent_id: str,
) -> bool:
    """
    After mTLS handshake, verify that the peer certificate's
    CN matches the expected agent_id.

    Raises ValueError if mismatch.
    Must be called after every connection to prevent agent
    impersonation.

    The ssl_socket parameter should be an ssl.SSLSocket or any
    object with a getpeercert(binary_form=True) method.
    """
    der_cert = ssl_socket.getpeercert(binary_form=True)  # type: ignore[attr-defined]
    if der_cert is None:
        raise ValueError(
            "No peer certificate presented — mTLS handshake incomplete."
        )
    cert = x509.load_der_x509_certificate(der_cert)
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs:
        raise ValueError("Peer certificate has no CN attribute.")
    cn = cn_attrs[0].value
    if cn != expected_agent_id:
        raise ValueError(
            f"Agent identity mismatch: cert CN={cn}, "
            f"expected={expected_agent_id}"
        )
    return True


# ---------------------------------------------------------------------------
# CA generation
# ---------------------------------------------------------------------------

def generate_ca(passphrase: str | bytes = "") -> tuple[bytes, bytes]:
    """
    Generate self-signed CA certificate and key.

    Uses EC P-256 for key generation and the cryptography library
    for certificate construction.
    Store CA cert and key in ~/.mahaguardian/certs/.
    Private key is encrypted at rest if passphrase is provided.
    Return (cert_pem_bytes, key_pem_bytes).
    """
    # Generate EC P-256 private key
    ca_key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "MahaGuardian CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MahaGuardian"),
    ])

    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    pw = _passphrase_bytes(passphrase) if passphrase else None
    encryption = BestAvailableEncryption(pw) if pw else serialization.NoEncryption()
    key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )

    # Persist
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    _write_pem(CA_CERT_PATH, cert_pem)
    _write_pem(CA_KEY_PATH, key_pem, private=True)

    audit.log(action="mtls.generate_ca", result="success")
    return cert_pem, key_pem


# ---------------------------------------------------------------------------
# Guardian certificate
# ---------------------------------------------------------------------------

def generate_guardian_cert(
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    passphrase: str | bytes = "",
) -> tuple[bytes, bytes]:
    """
    Generate certificate for the Guardian signed by the CA.

    Subject CN = "MahaGuardian Guardian".
    Store in ~/.mahaguardian/certs/guardian.crt and guardian.key.
    Private key is encrypted at rest if passphrase is provided.
    Return (cert_pem_bytes, key_pem_bytes).
    """
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    pw = _passphrase_bytes(passphrase) if passphrase else None
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=pw)

    guardian_key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "MahaGuardian Guardian"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MahaGuardian"),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(guardian_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    encryption = BestAvailableEncryption(pw) if pw else serialization.NoEncryption()
    key_pem = guardian_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )

    _write_pem(GUARDIAN_CERT_PATH, cert_pem)
    _write_pem(GUARDIAN_KEY_PATH, key_pem, private=True)

    audit.log(action="mtls.generate_guardian_cert", result="success")
    return cert_pem, key_pem


# ---------------------------------------------------------------------------
# Agent certificate
# ---------------------------------------------------------------------------

def generate_agent_cert(
    agent_id: str,
    ca_cert: bytes,
    ca_key: bytes,
    passphrase: str | bytes = "",
) -> tuple[bytes, bytes]:
    """
    Generate certificate for agent signed by CA.

    Include agent_id in Subject CN.
    Store in ~/.mahaguardian/certs/agents/{agent_id}.crt and .key.
    Private key is encrypted at rest if passphrase is provided.
    Return (cert_pem_bytes, key_pem_bytes).
    """
    _validate_agent_id(agent_id)

    ca_cert_obj = x509.load_pem_x509_certificate(ca_cert)
    pw = _passphrase_bytes(passphrase) if passphrase else None
    ca_key_obj = serialization.load_pem_private_key(ca_key, password=pw)

    agent_key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MahaGuardian Agent"),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert_obj.subject)
        .public_key(agent_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(agent_id)]),
            critical=False,
        )
        .sign(ca_key_obj, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    encryption = BestAvailableEncryption(pw) if pw else serialization.NoEncryption()
    key_pem = agent_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )

    AGENT_CERTS_DIR.mkdir(parents=True, exist_ok=True)
    agent_cert_path = AGENT_CERTS_DIR / f"{agent_id}.crt"
    agent_key_path = AGENT_CERTS_DIR / f"{agent_id}.key"
    _write_pem(agent_cert_path, cert_pem)
    _write_pem(agent_key_path, key_pem, private=True)

    audit.log(
        action="mtls.generate_agent_cert",
        agent_id=agent_id,
        result="success",
    )
    return cert_pem, key_pem


# ---------------------------------------------------------------------------
# SSL contexts
# ---------------------------------------------------------------------------

def guardian_mtls_client(
    agent_id: str,
    droplet_ip: str,
    droplet_port: int = 8443,
    passphrase: str | bytes = "",
) -> ssl.SSLContext:
    """
    Create mTLS client SSL context for Guardian.

    Guardian presents its own certificate.
    Guardian verifies agent certificate against CA.
    Return configured SSLContext.
    This is the outbound connection Guardian initiates.
    No inbound ports are opened on the user device.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(CA_CERT_PATH))
    pw = _passphrase_bytes(passphrase) if passphrase else None
    ctx.load_cert_chain(
        certfile=str(GUARDIAN_CERT_PATH),
        keyfile=str(GUARDIAN_KEY_PATH),
        password=pw,
    )
    ctx.verify_mode = ssl.CERT_REQUIRED
    # check_hostname is False because we connect by IP address, not hostname.
    # Agent identity MUST be verified after every connection by calling
    # verify_peer_agent_id(ssl_socket, agent_id) which checks the peer
    # certificate's CN against the expected agent_id.
    ctx.check_hostname = False

    audit.log(
        action="mtls.client_context",
        agent_id=agent_id,
        resource=f"{droplet_ip}:{droplet_port}",
        result="success",
    )
    return ctx


def agent_mtls_server(agent_id: str, passphrase: str | bytes = "") -> ssl.SSLContext:
    """
    Create mTLS server SSL context for agent on droplet.

    Agent presents its certificate.
    Agent verifies Guardian certificate against CA.
    Only Guardian's certificate is accepted.
    Return configured SSLContext.
    """
    _validate_agent_id(agent_id)
    agent_cert_path = AGENT_CERTS_DIR / f"{agent_id}.crt"
    agent_key_path = AGENT_CERTS_DIR / f"{agent_id}.key"

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cafile=str(CA_CERT_PATH))
    pw = _passphrase_bytes(passphrase) if passphrase else None
    ctx.load_cert_chain(
        certfile=str(agent_cert_path),
        keyfile=str(agent_key_path),
        password=pw,
    )
    # Require Guardian to present a valid certificate
    ctx.verify_mode = ssl.CERT_REQUIRED

    audit.log(
        action="mtls.server_context",
        agent_id=agent_id,
        result="success",
    )
    return ctx
