"""
Tests for guardian/mtls.py — mTLS certificate generation and connection.
"""
from __future__ import annotations

import os
import platform
import ssl
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import guardian.audit as audit_module
import guardian.mtls as mtls_module
from guardian.mtls import (
    generate_agent_cert,
    generate_ca,
    generate_guardian_cert,
    guardian_mtls_client,
    agent_mtls_server,
    verify_peer_agent_id,
)

CERT_PASSPHRASE = "test-cert-passphrase"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_audit(tmp_path):
    audit_db = tmp_path / "audit.db"
    audit_module.init_audit_log(audit_db)
    yield


@pytest.fixture(autouse=True)
def isolated_cert_paths(tmp_path, monkeypatch):
    """Redirect all cert paths to temp directory."""
    certs_dir = tmp_path / "certs"
    agents_dir = certs_dir / "agents"
    certs_dir.mkdir(parents=True)
    agents_dir.mkdir(parents=True)

    monkeypatch.setattr(mtls_module, "CERTS_DIR", certs_dir)
    monkeypatch.setattr(mtls_module, "CA_CERT_PATH", certs_dir / "ca.crt")
    monkeypatch.setattr(mtls_module, "CA_KEY_PATH", certs_dir / "ca.key")
    monkeypatch.setattr(mtls_module, "GUARDIAN_CERT_PATH", certs_dir / "guardian.crt")
    monkeypatch.setattr(mtls_module, "GUARDIAN_KEY_PATH", certs_dir / "guardian.key")
    monkeypatch.setattr(mtls_module, "AGENT_CERTS_DIR", agents_dir)

    yield tmp_path


@pytest.fixture
def ca_certs(isolated_cert_paths):
    """Generate CA and return (cert_pem, key_pem)."""
    return generate_ca(CERT_PASSPHRASE)


@pytest.fixture
def guardian_certs(ca_certs):
    """Generate Guardian cert and return (cert_pem, key_pem)."""
    ca_cert, ca_key = ca_certs
    return generate_guardian_cert(ca_cert, ca_key, CERT_PASSPHRASE)


@pytest.fixture
def agent_certs(ca_certs):
    """Generate agent cert and return (cert_pem, key_pem)."""
    ca_cert, ca_key = ca_certs
    return generate_agent_cert("alpha", ca_cert, ca_key, CERT_PASSPHRASE)


# ---------------------------------------------------------------------------
# generate_ca
# ---------------------------------------------------------------------------

class TestGenerateCA:
    def test_returns_pem_bytes(self, ca_certs):
        cert_pem, key_pem = ca_certs
        assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert key_pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")

    def test_cert_is_self_signed(self, ca_certs):
        cert_pem, _ = ca_certs
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert.issuer == cert.subject

    def test_cert_is_ca(self, ca_certs):
        cert_pem, _ = ca_certs
        cert = x509.load_pem_x509_certificate(cert_pem)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_cn_is_mahaguardian_ca(self, ca_certs):
        cert_pem, _ = ca_certs
        cert = x509.load_pem_x509_certificate(cert_pem)
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn[0].value == "MahaGuardian CA"

    def test_key_is_ec_p256(self, ca_certs):
        _, key_pem = ca_certs
        key = serialization.load_pem_private_key(key_pem, password=CERT_PASSPHRASE.encode())
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, ec.SECP256R1)

    def test_files_written_to_disk(self, isolated_cert_paths, ca_certs):
        certs_dir = isolated_cert_paths / "certs"
        assert (certs_dir / "ca.crt").exists()
        assert (certs_dir / "ca.key").exists()

    def test_audit_logged(self, ca_certs):
        entries = audit_module.query_log(action="mtls.generate_ca")
        assert len(entries) >= 1

    @pytest.mark.skipif(
        platform.system() == "Windows",
        reason="0o600 permissions are a Unix concept",
    )
    def test_ca_key_permissions(self, isolated_cert_paths, ca_certs):
        ca_key_path = isolated_cert_paths / "certs" / "ca.key"
        mode = ca_key_path.stat().st_mode & 0o777
        assert mode == 0o600


# ---------------------------------------------------------------------------
# generate_guardian_cert
# ---------------------------------------------------------------------------

class TestGenerateGuardianCert:
    def test_returns_pem_bytes(self, guardian_certs):
        cert_pem, key_pem = guardian_certs
        assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert key_pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")

    def test_signed_by_ca(self, ca_certs, guardian_certs):
        ca_cert_pem, _ = ca_certs
        guardian_cert_pem, _ = guardian_certs
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        guardian_cert = x509.load_pem_x509_certificate(guardian_cert_pem)
        assert guardian_cert.issuer == ca_cert.subject

    def test_cn_is_guardian(self, guardian_certs):
        cert_pem, _ = guardian_certs
        cert = x509.load_pem_x509_certificate(cert_pem)
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn[0].value == "MahaGuardian Guardian"

    def test_not_ca(self, guardian_certs):
        cert_pem, _ = guardian_certs
        cert = x509.load_pem_x509_certificate(cert_pem)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_has_client_auth_eku(self, guardian_certs):
        cert_pem, _ = guardian_certs
        cert = x509.load_pem_x509_certificate(cert_pem)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    def test_files_written(self, isolated_cert_paths, guardian_certs):
        certs_dir = isolated_cert_paths / "certs"
        assert (certs_dir / "guardian.crt").exists()
        assert (certs_dir / "guardian.key").exists()

    def test_audit_logged(self, guardian_certs):
        entries = audit_module.query_log(action="mtls.generate_guardian_cert")
        assert len(entries) >= 1


# ---------------------------------------------------------------------------
# generate_agent_cert
# ---------------------------------------------------------------------------

class TestGenerateAgentCert:
    def test_returns_pem_bytes(self, agent_certs):
        cert_pem, key_pem = agent_certs
        assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert key_pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")

    def test_signed_by_ca(self, ca_certs, agent_certs):
        ca_cert_pem, _ = ca_certs
        agent_cert_pem, _ = agent_certs
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        agent_cert = x509.load_pem_x509_certificate(agent_cert_pem)
        assert agent_cert.issuer == ca_cert.subject

    def test_cn_is_agent_id(self, agent_certs):
        cert_pem, _ = agent_certs
        cert = x509.load_pem_x509_certificate(cert_pem)
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn[0].value == "alpha"

    def test_has_san_with_agent_id(self, agent_certs):
        cert_pem, _ = agent_certs
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "alpha" in dns_names

    def test_has_server_auth_eku(self, agent_certs):
        cert_pem, _ = agent_certs
        cert = x509.load_pem_x509_certificate(cert_pem)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku.value

    def test_not_ca(self, agent_certs):
        cert_pem, _ = agent_certs
        cert = x509.load_pem_x509_certificate(cert_pem)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_files_written(self, isolated_cert_paths, agent_certs):
        agents_dir = isolated_cert_paths / "certs" / "agents"
        assert (agents_dir / "alpha.crt").exists()
        assert (agents_dir / "alpha.key").exists()

    def test_different_agents_get_different_certs(self, ca_certs):
        ca_cert, ca_key = ca_certs
        cert1, _ = generate_agent_cert("alpha", ca_cert, ca_key, CERT_PASSPHRASE)
        cert2, _ = generate_agent_cert("beta", ca_cert, ca_key, CERT_PASSPHRASE)
        assert cert1 != cert2

    def test_audit_logged(self, agent_certs):
        entries = audit_module.query_log(action="mtls.generate_agent_cert")
        assert len(entries) >= 1
        assert entries[-1]["agent_id"] == "alpha"

    @pytest.mark.skipif(
        platform.system() == "Windows",
        reason="0o600 permissions are a Unix concept",
    )
    def test_agent_key_permissions(self, isolated_cert_paths, agent_certs):
        key_path = isolated_cert_paths / "certs" / "agents" / "alpha.key"
        mode = key_path.stat().st_mode & 0o777
        assert mode == 0o600


# ---------------------------------------------------------------------------
# SSL contexts
# ---------------------------------------------------------------------------

class TestGuardianMtlsClient:
    def test_returns_ssl_context(self, guardian_certs, agent_certs):
        ctx = guardian_mtls_client("alpha", "10.0.0.1", passphrase=CERT_PASSPHRASE)
        assert isinstance(ctx, ssl.SSLContext)

    def test_verify_mode_required(self, guardian_certs, agent_certs):
        ctx = guardian_mtls_client("alpha", "10.0.0.1", passphrase=CERT_PASSPHRASE)
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_check_hostname_disabled(self, guardian_certs, agent_certs):
        ctx = guardian_mtls_client("alpha", "10.0.0.1", passphrase=CERT_PASSPHRASE)
        assert ctx.check_hostname is False

    def test_audit_logged(self, guardian_certs, agent_certs):
        guardian_mtls_client("alpha", "10.0.0.1", passphrase=CERT_PASSPHRASE)
        entries = audit_module.query_log(action="mtls.client_context")
        assert len(entries) >= 1


class TestAgentMtlsServer:
    def test_returns_ssl_context(self, guardian_certs, agent_certs):
        ctx = agent_mtls_server("alpha", passphrase=CERT_PASSPHRASE)
        assert isinstance(ctx, ssl.SSLContext)

    def test_verify_mode_required(self, guardian_certs, agent_certs):
        ctx = agent_mtls_server("alpha", passphrase=CERT_PASSPHRASE)
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_audit_logged(self, guardian_certs, agent_certs):
        agent_mtls_server("alpha", passphrase=CERT_PASSPHRASE)
        entries = audit_module.query_log(action="mtls.server_context")
        assert len(entries) >= 1


# ---------------------------------------------------------------------------
# verify_peer_agent_id (FIX A)
# ---------------------------------------------------------------------------

class TestVerifyPeerAgentId:
    def test_matching_cn_passes(self, agent_certs):
        """Cert with CN=alpha passes for expected_agent_id=alpha."""
        cert_pem, _ = agent_certs
        cert = x509.load_pem_x509_certificate(cert_pem)
        der_cert = cert.public_bytes(serialization.Encoding.DER)
        mock_socket = MagicMock()
        mock_socket.getpeercert.return_value = der_cert
        assert verify_peer_agent_id(mock_socket, "alpha") is True

    def test_mismatched_cn_raises(self, agent_certs):
        """Cert with CN=alpha raises for expected_agent_id=beta."""
        cert_pem, _ = agent_certs
        cert = x509.load_pem_x509_certificate(cert_pem)
        der_cert = cert.public_bytes(serialization.Encoding.DER)
        mock_socket = MagicMock()
        mock_socket.getpeercert.return_value = der_cert
        with pytest.raises(ValueError, match="mismatch.*alpha.*beta"):
            verify_peer_agent_id(mock_socket, "beta")

    def test_no_peer_cert_raises(self):
        """Missing peer cert raises ValueError."""
        mock_socket = MagicMock()
        mock_socket.getpeercert.return_value = None
        with pytest.raises(ValueError, match="No peer certificate"):
            verify_peer_agent_id(mock_socket, "alpha")


# ---------------------------------------------------------------------------
# Agent ID validation (FIX D)
# ---------------------------------------------------------------------------

class TestAgentIdValidation:
    def test_path_traversal_rejected(self, ca_certs):
        ca_cert, ca_key = ca_certs
        with pytest.raises(ValueError, match="Invalid agent_id"):
            generate_agent_cert("../../etc/passwd", ca_cert, ca_key, CERT_PASSPHRASE)

    def test_slash_rejected(self, ca_certs):
        ca_cert, ca_key = ca_certs
        with pytest.raises(ValueError, match="Invalid agent_id"):
            generate_agent_cert("alpha/beta", ca_cert, ca_key, CERT_PASSPHRASE)

    def test_spaces_rejected(self, ca_certs):
        ca_cert, ca_key = ca_certs
        with pytest.raises(ValueError, match="Invalid agent_id"):
            generate_agent_cert("alpha beta", ca_cert, ca_key, CERT_PASSPHRASE)

    def test_valid_agent_id_accepted(self, ca_certs):
        ca_cert, ca_key = ca_certs
        cert, key = generate_agent_cert("alpha-01_test", ca_cert, ca_key, CERT_PASSPHRASE)
        assert cert.startswith(b"-----BEGIN CERTIFICATE-----")

    def test_empty_agent_id_rejected(self, ca_certs):
        ca_cert, ca_key = ca_certs
        with pytest.raises(ValueError, match="Invalid agent_id"):
            generate_agent_cert("", ca_cert, ca_key, CERT_PASSPHRASE)


# ---------------------------------------------------------------------------
# Private key encryption at rest (F-003)
# ---------------------------------------------------------------------------

class TestPrivateKeyEncryption:
    def test_ca_key_file_is_encrypted(self, isolated_cert_paths):
        generate_ca(CERT_PASSPHRASE)
        ca_key_path = isolated_cert_paths / "certs" / "ca.key"
        content = ca_key_path.read_bytes()
        assert b"ENCRYPTED PRIVATE KEY" in content

    def test_load_ca_key_without_passphrase_fails(self, ca_certs):
        _, key_pem = ca_certs
        with pytest.raises((TypeError, ValueError)):
            serialization.load_pem_private_key(key_pem, password=None)

    def test_load_ca_key_with_passphrase_succeeds(self, ca_certs):
        _, key_pem = ca_certs
        key = serialization.load_pem_private_key(
            key_pem, password=CERT_PASSPHRASE.encode()
        )
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_encrypted_keys_produce_valid_certs(self, ca_certs):
        ca_cert_pem, ca_key_pem = ca_certs
        # Guardian cert signed by encrypted CA key still verifies
        g_cert_pem, _ = generate_guardian_cert(
            ca_cert_pem, ca_key_pem, CERT_PASSPHRASE
        )
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        g_cert = x509.load_pem_x509_certificate(g_cert_pem)
        assert g_cert.issuer == ca_cert.subject
