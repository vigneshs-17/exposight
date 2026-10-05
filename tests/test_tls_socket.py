"""v3.6b B-2: TLS socket inspection with real local TLS servers.

Covers bug a (TLS 1.0/1.1 never detected), bug b (untrusted certificates lost their
expiry and names) and R2 (the fallback connection obeys the same SSRF rules).
No real network: servers listen on 127.0.0.1, and the resolver is a fake that
returns a public documentation IP; the socket connect is redirected to the local
server while recording which address the code asked for.
"""

import datetime
import socket
import ssl
import threading
import warnings
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from asm import tls_inspect
from asm.tls_inspect import cert_dict_from_der, connect_and_inspect_cert_socket

HOST = "legacy.example.com"
PUBLIC_IP = "93.184.216.34"


class FakeResolver:
    """Stands in for dns.resolver.Resolver; returns fixed answers, never touches the network."""

    def __init__(self, a_records: list[str]) -> None:
        self.a_records = a_records
        self.lifetime = self.timeout = 0

    def resolve(self, hostname, rdtype):
        import dns.resolver

        if rdtype != "A" or not self.a_records:
            raise dns.resolver.NoAnswer()

        class _Rdata:
            def __init__(self, ip):
                self.ip = ip

            def to_text(self):
                return self.ip

        return [_Rdata(ip) for ip in self.a_records]


def _key_and_name(cn: str):
    return ec.generate_private_key(ec.SECP256R1()), x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    )


def _write_pem(path: Path, cert, key) -> tuple[str, str]:
    cert_file, key_file = path / f"{cert.serial_number}.crt", path / f"{cert.serial_number}.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_file), str(key_file)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A test CA, a leaf certificate it signed, and a self-signed certificate."""
    tmp = tmp_path_factory.mktemp("pki")
    now = datetime.datetime.now(datetime.UTC)
    ca_key, ca_name = _key_and_name("Exposight Test CA")
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key, leaf_name = _key_and_name(HOST)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=60))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
        # Python 3.13+ verifies with VERIFY_X509_STRICT, which requires these.
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    self_key, self_name = _key_and_name(HOST)
    self_signed = (
        x509.CertificateBuilder()
        .subject_name(self_name)
        .issuer_name(self_name)
        .public_key(self_key.public_key())
        .serial_number(0xBEEF)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(HOST), x509.DNSName("alt." + HOST)]),
            critical=False,
        )
        .sign(self_key, hashes.SHA256())
    )
    ca_file = tmp / "ca.pem"
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return {
        "ca_file": str(ca_file),
        "leaf": _write_pem(tmp, leaf, leaf_key),
        "self_signed": _write_pem(tmp, self_signed, self_key),
        "self_signed_der": self_signed.public_bytes(serialization.Encoding.DER),
    }


@pytest.fixture
def tls_server():
    """Start a local TLS server: tls_server(cert_and_key, max_version) -> port."""
    servers = []

    def start(cert_and_key, max_version=ssl.TLSVersion.MAXIMUM_SUPPORTED) -> int:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*cert_and_key)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = max_version
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        srv.settimeout(10)

        def serve():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                try:
                    with ctx.wrap_socket(conn, server_side=True) as tls:
                        tls.settimeout(2)
                        tls.recv(1)
                except (OSError, ssl.SSLError):
                    pass

        threading.Thread(target=serve, daemon=True).start()
        servers.append(srv)
        return srv.getsockname()[1]

    yield start
    for srv in servers:
        srv.close()


@pytest.fixture
def connect_log(monkeypatch):
    """Redirect sockets to the local server; record the (ip, port) the code asked for."""
    requested: list[tuple[str, int]] = []
    real_create_connection = socket.create_connection
    target = {"port": None}

    def fake_create_connection(address, timeout=None, *args, **kwargs):
        requested.append(address)
        return real_create_connection(("127.0.0.1", target["port"]), timeout=timeout)

    monkeypatch.setattr(tls_inspect.socket, "create_connection", fake_create_connection)
    return requested, target


@pytest.fixture
def trust_test_ca(monkeypatch, pki):
    """Make verified contexts trust the test CA (in addition to the system store)."""
    real = ssl.create_default_context

    def with_test_ca(*args, **kwargs):
        ctx = real(*args, **kwargs)
        ctx.load_verify_locations(cafile=pki["ca_file"])
        return ctx

    monkeypatch.setattr(tls_inspect.ssl, "create_default_context", with_test_ca)


def _inspect():
    return connect_and_inspect_cert_socket(
        HOST, port=443, timeout=3, resolver=FakeResolver([PUBLIC_IP])
    )


# --- bug a: old protocols are now detected --------------------------------------------


@pytest.mark.parametrize(
    ("max_version", "expected"),
    [(ssl.TLSVersion.TLSv1, "TLSv1"), (ssl.TLSVersion.TLSv1_1, "TLSv1.1")],
)
def test_legacy_only_host_with_valid_cert_is_trusted_but_deprecated(
    pki, tls_server, connect_log, trust_test_ca, max_version, expected
):
    requested, target = connect_log
    target["port"] = tls_server(pki["leaf"], max_version)

    cert = _inspect()

    assert cert is not None, "old-protocol host was reported as unreachable"
    assert cert.tls_version == expected
    assert cert.deprecated_tls is True
    assert cert.is_trusted is True
    assert cert.sans == [HOST]


def test_modern_host_is_trusted_and_not_deprecated(pki, tls_server, connect_log, trust_test_ca):
    _, target = connect_log
    target["port"] = tls_server(pki["leaf"])
    cert = _inspect()
    assert cert.is_trusted is True
    assert cert.deprecated_tls is False
    assert cert.tls_version in ("TLSv1.2", "TLSv1.3")


def test_legacy_context_allows_tls1():
    ctx = tls_inspect._legacy_context(verify=False)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1
    assert ctx.verify_mode == ssl.CERT_NONE


# --- bug b: untrusted certificates keep their details ---------------------------------


def test_untrusted_cert_keeps_expiry_names_and_issuer(pki, tls_server, connect_log):
    _, target = connect_log
    target["port"] = tls_server(pki["self_signed"], ssl.TLSVersion.TLSv1)

    cert = _inspect()

    assert cert.is_trusted is False
    assert cert.verify_error  # why verification failed is still recorded
    assert cert.sans == [HOST, "alt." + HOST]
    assert cert.subject_cn == HOST
    assert cert.not_after != ""
    assert 8 <= cert.days_until_expiry <= 10
    assert cert.issuer_equals_subject is True
    assert cert.serial_hex == "BEEF"
    assert cert.tls_version == "TLSv1"
    assert cert.deprecated_tls is True


def test_cert_dict_from_der_matches_getpeercert_format(pki):
    cert_dict = cert_dict_from_der(pki["self_signed_der"])
    assert cert_dict["subject"] == ((("commonName", HOST),),)
    assert cert_dict["subjectAltName"] == (("DNS", HOST), ("DNS", "alt." + HOST))
    assert cert_dict["notAfter"].endswith(" GMT")
    ssl.cert_time_to_seconds(cert_dict["notAfter"])  # parses like a real getpeercert() value


def test_cert_dict_from_der_rejects_garbage():
    with pytest.raises(ValueError):
        cert_dict_from_der(b"not a certificate")


# --- R2: every connection obeys the SSRF rules ----------------------------------------


def test_connects_only_to_the_validated_ip_with_sni(pki, tls_server, connect_log):
    requested, target = connect_log
    target["port"] = tls_server(pki["self_signed"], ssl.TLSVersion.TLSv1)
    _inspect()
    assert requested, "no connection was made"
    assert set(requested) == {(PUBLIC_IP, 443)}  # never the hostname, never another IP


@pytest.mark.parametrize(
    "answers",
    [
        ["10.0.0.5"],
        ["127.0.0.1"],
        ["169.254.169.254"],
        [PUBLIC_IP, "192.168.1.10"],  # one private answer is enough to refuse
        [],  # unresolved: fail closed
    ],
)
def test_private_or_unresolved_host_is_refused_before_any_connection(answers):
    with patch.object(
        tls_inspect.socket, "create_connection", side_effect=OSError("must not connect")
    ) as create_connection:
        result = connect_and_inspect_cert_socket(HOST, resolver=FakeResolver(answers))
    assert result is None
    create_connection.assert_not_called()
