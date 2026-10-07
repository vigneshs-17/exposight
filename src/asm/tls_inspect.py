"""TLS certificate inspection and validation for Exposight.

Extracts certificate details, verifies trust, evaluates expiry and hostname
matching, and flags certificate anomalies (expired, expiring soon, self-signed,
hostname mismatch, deprecated TLS versions).
"""

from __future__ import annotations

import datetime
import logging
import socket
import ssl
import warnings
from typing import Any

import dns.resolver
from cryptography import x509
from cryptography.x509.oid import NameOID

from asm.models import CertInfo
from asm.scan_common import pin_host

logger = logging.getLogger(__name__)

DEPRECATED_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


def matches_hostname(
    hostname: str,
    san_dns_list: list[str],
    common_name: str | None,
) -> bool:
    """Check if hostname matches any SAN DNS entry or common name (RFC 6125).

    Evaluates exact matches and single-level wildcard domains (*.example.com).
    Wildcards only match a single DNS label.

    Args:
        hostname: The hostname being checked.
        san_dns_list: List of DNS names from Subject Alternative Names.
        common_name: Common Name (CN) from Subject.

    Returns:
        True if the hostname matches, False otherwise.
    """
    # Prefer SAN if present; fallback to CN if no SANs exist
    names_to_check = san_dns_list if san_dns_list else ([common_name] if common_name else [])
    clean_host = hostname.lower().strip(".")

    for pattern in names_to_check:
        clean_pattern = pattern.lower().strip(".")
        if clean_pattern.startswith("*."):
            # Single-level wildcard match (e.g. *.example.com matches sub.example.com)
            wildcard_suffix = clean_pattern[2:]
            if clean_host.endswith("." + wildcard_suffix):
                prefix = clean_host[: -(len(wildcard_suffix) + 1)]
                # Wildcard cannot span multiple dots (e.g. a.b.example.com does not match
                # *.example.com)
                if "." not in prefix and prefix:
                    return True
        elif clean_host == clean_pattern:
            return True

    return False


def format_rdn_tuple(rdn_tuple: tuple[Any, ...]) -> str:
    """Format an OpenSSL RDN tuple into a readable distinguished name string.

    Example input: ((('countryName', 'US'),), (('commonName', 'example.com'),))
    Example output: 'C=US, CN=example.com'

    Args:
        rdn_tuple: Nested tuple of attributes from ssl.getpeercert().

    Returns:
        Formatted comma-separated string.
    """
    if not rdn_tuple:
        return ""

    short_names = {
        "commonName": "CN",
        "organizationName": "O",
        "organizationalUnitName": "OU",
        "countryName": "C",
        "stateOrProvinceName": "ST",
        "localityName": "L",
    }

    parts: list[str] = []
    for rdn in rdn_tuple:
        for attr, val in rdn:
            key = short_names.get(attr, attr)
            parts.append(f"{key}={val}")

    return ", ".join(parts)


def extract_cn(rdn_tuple: tuple[Any, ...]) -> str | None:
    """Extract commonName value from an OpenSSL RDN tuple.

    Args:
        rdn_tuple: Nested tuple of attributes from ssl.getpeercert().

    Returns:
        Common Name string if found, None otherwise.
    """
    if not rdn_tuple:
        return None

    for rdn in rdn_tuple:
        for attr, val in rdn:
            if attr == "commonName":
                return str(val)

    return None


def parse_cert_dict(
    cert_dict: dict[str, Any],
    hostname: str,
    tls_version: str | None,
    is_trusted: bool,
    verify_error: str | None,
    source: str = "from_response",
    now_utc: datetime.datetime | None = None,
) -> CertInfo:
    """Parse a certificate dictionary from getpeercert() into a CertInfo model.

    Args:
        cert_dict: Parsed certificate dictionary from ssl.getpeercert().
        hostname: Hostname that was scanned.
        tls_version: Negotiated TLS protocol version (e.g. 'TLSv1.3').
        is_trusted: Whether the certificate verified against the system CA store.
        verify_error: Verification error message if verification failed.
        source: Method used ('from_response' or 'from_socket').
        now_utc: Optional current UTC datetime for testing.

    Returns:
        Populated CertInfo dataclass with flags.
    """
    if now_utc is None:
        now_utc = datetime.datetime.now(datetime.UTC)

    # 1. Subject CN and SANs
    subject_tuple = cert_dict.get("subject", ())
    issuer_tuple = cert_dict.get("issuer", ())
    subject_cn = extract_cn(subject_tuple)
    issuer_str = format_rdn_tuple(issuer_tuple)

    sans: list[str] = []
    for typ, val in cert_dict.get("subjectAltName", ()):
        if typ.lower() == "dns":
            sans.append(val)

    # 2. Validity period
    not_before_str = cert_dict.get("notBefore", "")
    not_after_str = cert_dict.get("notAfter", "")

    not_before_iso = ""
    not_after_iso = ""
    days_until_expiry = 0.0
    expired = False
    not_yet_valid = False

    if not_before_str:
        try:
            nb_secs = ssl.cert_time_to_seconds(not_before_str)
            nb_dt = datetime.datetime.fromtimestamp(nb_secs, tz=datetime.UTC)
            not_before_iso = nb_dt.isoformat()
            if now_utc < nb_dt:
                not_yet_valid = True
        except (ValueError, TypeError, OverflowError, OSError) as exc:
            # Malformed notBefore from an untrusted certificate: leave the field empty.
            logger.debug("Unparseable certificate notBefore %r: %s", not_before_str, exc)

    if not_after_str:
        try:
            na_secs = ssl.cert_time_to_seconds(not_after_str)
            na_dt = datetime.datetime.fromtimestamp(na_secs, tz=datetime.UTC)
            not_after_iso = na_dt.isoformat()
            diff_secs = (na_dt - now_utc).total_seconds()
            days_until_expiry = round(diff_secs / 86400, 1)
            if now_utc > na_dt or diff_secs < 0:
                expired = True
        except (ValueError, TypeError, OverflowError, OSError) as exc:
            # Malformed notAfter from an untrusted certificate: leave expiry unknown.
            logger.debug("Unparseable certificate notAfter %r: %s", not_after_str, exc)

    # 3. Serial number & flags
    serial_hex = cert_dict.get("serialNumber")
    if serial_hex and not isinstance(serial_hex, str):
        serial_hex = str(serial_hex)

    # Hostname matching (RFC 6125)
    hostname_matches = matches_hostname(hostname, sans, subject_cn)
    hostname_mismatch = not hostname_matches

    # Issuer equals subject (indicates a likely self-signed certificate, not definitive proof
    # of untrust)
    issuer_equals_subject = bool(subject_tuple and subject_tuple == issuer_tuple)

    # Expiring soon: between 0 and 30 days remaining
    expiring_soon = not expired and (0.0 <= days_until_expiry <= 30.0)

    # Deprecated TLS version negotiated
    deprecated_tls = bool(tls_version and tls_version in DEPRECATED_TLS_VERSIONS)

    return CertInfo(
        subject_cn=subject_cn,
        sans=sans,
        issuer=issuer_str,
        not_before=not_before_iso,
        not_after=not_after_iso,
        days_until_expiry=days_until_expiry,
        serial_hex=serial_hex,
        tls_version=tls_version,
        hostname_matches=hostname_matches,
        is_trusted=is_trusted,
        verify_error=verify_error,
        source=source,
        expired=expired,
        not_yet_valid=not_yet_valid,
        issuer_equals_subject=issuer_equals_subject,
        hostname_mismatch=hostname_mismatch,
        expiring_soon=expiring_soon,
        deprecated_tls=deprecated_tls,
    )


_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

# cryptography OID -> attribute names used by ssl.getpeercert(), so parse_cert_dict
# handles certificates from both sources the same way.
_GETPEERCERT_NAMES = {
    NameOID.COMMON_NAME: "commonName",
    NameOID.ORGANIZATION_NAME: "organizationName",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
    NameOID.COUNTRY_NAME: "countryName",
    NameOID.STATE_OR_PROVINCE_NAME: "stateOrProvinceName",
    NameOID.LOCALITY_NAME: "localityName",
}


def _getpeercert_time(value: datetime.datetime) -> str:
    """Format a UTC datetime the way ssl.getpeercert() does ('Jun  1 12:00:00 2026 GMT')."""
    return (
        f"{_MONTHS[value.month - 1]} {value.day:2d} "
        f"{value.hour:02d}:{value.minute:02d}:{value.second:02d} {value.year} GMT"
    )


def _getpeercert_name(name: x509.Name) -> tuple[tuple[tuple[str, str], ...], ...]:
    """Convert a cryptography Name into getpeercert()'s nested RDN tuple."""
    return tuple(
        tuple(
            (_GETPEERCERT_NAMES.get(attr.oid, attr.oid.dotted_string), str(attr.value))
            for attr in rdn
        )
        for rdn in name.rdns
    )


def cert_dict_from_der(der_bytes: bytes) -> dict[str, Any]:
    """Parse a DER certificate into the dict format of ssl.getpeercert().

    Used for untrusted certificates: with verification disabled, getpeercert()
    returns {} and only the raw DER bytes are available.

    Raises:
        ValueError: If the bytes are not a valid X.509 certificate.
    """
    cert = x509.load_der_x509_certificate(der_bytes)
    sans: list[tuple[str, str]] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans += [("DNS", n) for n in san_ext.value.get_values_for_type(x509.DNSName)]
        sans += [
            ("IP Address", str(ip)) for ip in san_ext.value.get_values_for_type(x509.IPAddress)
        ]
    except x509.ExtensionNotFound:
        pass
    return {
        "subject": _getpeercert_name(cert.subject),
        "issuer": _getpeercert_name(cert.issuer),
        "notBefore": _getpeercert_time(cert.not_valid_before_utc),
        "notAfter": _getpeercert_time(cert.not_valid_after_utc),
        "serialNumber": format(cert.serial_number, "X"),
        "subjectAltName": tuple(sans),
    }


def resolve_safe_ip(
    hostname: str, resolver: dns.resolver.Resolver | None = None
) -> tuple[str | None, str | None]:
    """Resolve hostname with the same SSRF rules as the main inspection path.

    Returns (ip, None) when EVERY resolved address is public (the IP chosen by
    pick_ip), otherwise (None, reason). The caller connects to that IP itself, so
    the socket cannot be steered to a different address by a second lookup.
    """
    return pin_host(hostname, {}, resolver=resolver)


def _legacy_context(verify: bool) -> ssl.SSLContext:
    """TLS context that can still negotiate TLS 1.0/1.1 so old protocols are detected.

    Python's default client context refuses anything below TLS 1.2, which made the
    deprecated-protocol finding impossible to trigger. Whether TLS 1.0 really
    works also depends on the OpenSSL build; @SECLEVEL=0 lifts OpenSSL's own floor.
    """
    ctx = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except ValueError:
            logger.debug("This OpenSSL build cannot lower the minimum TLS version")
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        logger.debug("This OpenSSL build rejected @SECLEVEL=0")
    return ctx


def _handshake(
    ip: str, hostname: str, port: int, timeout: float, ctx: ssl.SSLContext
) -> tuple[str | None, dict[str, Any], bytes | None]:
    """Connect to the already-validated IP with SNI = hostname.

    Returns (tls_version, getpeercert(), DER bytes).
    """
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as sslsock:
            return (
                sslsock.version(),
                sslsock.getpeercert() or {},
                sslsock.getpeercert(binary_form=True),
            )


def _cert_info(
    hostname: str,
    tls_version: str | None,
    cert_dict: dict[str, Any],
    der: bytes | None,
    trusted: bool,
    verify_error: str | None,
    now_utc: datetime.datetime | None,
) -> CertInfo:
    """Build CertInfo from a completed handshake, parsing DER when the dict is empty."""
    if not cert_dict and der:
        try:
            cert_dict = cert_dict_from_der(der)
        except ValueError as exc:
            logger.debug("Could not parse DER certificate from %s: %s", hostname, exc)
    if cert_dict:
        return parse_cert_dict(
            cert_dict=cert_dict,
            hostname=hostname,
            tls_version=tls_version,
            is_trusted=trusted,
            verify_error=None if trusted else verify_error,
            source="from_socket",
            now_utc=now_utc,
        )
    # No certificate bytes at all: fall back to what the verification error says.
    err_lower = (verify_error or "").lower()
    hostname_mismatch = "hostname" in err_lower or "match" in err_lower
    return CertInfo(
        subject_cn=None,
        sans=[],
        issuer="",
        not_before="",
        not_after="",
        days_until_expiry=0.0,
        serial_hex=None,
        tls_version=tls_version,
        hostname_matches=not hostname_mismatch,
        is_trusted=trusted,
        verify_error=verify_error,
        source="from_socket",
        expired="expired" in err_lower,
        not_yet_valid=False,
        issuer_equals_subject="self signed" in err_lower or "self-signed" in err_lower,
        hostname_mismatch=hostname_mismatch,
        expiring_soon=False,
        deprecated_tls=bool(tls_version and tls_version in DEPRECATED_TLS_VERSIONS),
    )


def connect_and_inspect_cert_socket(
    hostname: str,
    port: int = 443,
    timeout: float = 5.0,
    now_utc: datetime.datetime | None = None,
    resolver: dns.resolver.Resolver | None = None,
    ip: str | None = None,
) -> CertInfo | None:
    """Connect directly with ssl+socket to retrieve and evaluate a host's certificate.

    SSRF: the host is resolved once and every address must be public (the same rule
    as the main inspection path). All handshakes connect to that validated IP with
    SNI set to the hostname, so a private, loopback or metadata address is never
    contacted, not even by the legacy-protocol fallback.

    Passes:
    1. Verified, modern defaults (TLS 1.2+).
    2. If pass 1 failed for a protocol reason (not a certificate reason): verified
       with TLS 1.0/1.1 allowed, so an old-protocol host with a valid certificate is
       reported as trusted but deprecated.
    3. Otherwise: unverified with TLS 1.0/1.1 allowed. Verification is off only to
       read and report the bad certificate (is_trusted=False); nothing from this
       connection is trusted. Details come from the DER bytes, because
       getpeercert() returns {} when verification is off.

    ip: an address the caller already validated and pinned for hostname; when
    given, no new lookup is made.

    Returns:
        Populated CertInfo, or None if the host is unsafe or unreachable.
    """
    unsafe_reason = None
    if ip is None:
        ip, unsafe_reason = resolve_safe_ip(hostname, resolver=resolver)
    if ip is None:
        logger.info(
            "TLS socket inspection refused for %s (SSRF guard): %s", hostname, unsafe_reason
        )
        return None

    verify_error: str | None = None
    try:
        version, cert_dict, der = _handshake(
            ip, hostname, port, timeout, ssl.create_default_context()
        )
        return _cert_info(hostname, version, cert_dict, der, True, None, now_utc)
    except ssl.SSLCertVerificationError as exc:
        verify_error = str(exc)
    except ssl.SSLError as exc:
        verify_error = str(exc)
        try:
            version, cert_dict, der = _handshake(
                ip, hostname, port, timeout, _legacy_context(verify=True)
            )
            return _cert_info(hostname, version, cert_dict, der, True, None, now_utc)
        except ssl.SSLCertVerificationError as legacy_exc:
            verify_error = str(legacy_exc)
        except ssl.SSLError:
            pass
        except (OSError, TimeoutError) as net_err:
            logger.debug("TLS port %d unreachable on %s: %s", port, hostname, net_err)
            return None
    except (OSError, TimeoutError) as net_err:
        logger.debug("TLS port %d unreachable on %s: %s", port, hostname, net_err)
        return None

    try:
        version, cert_dict, der = _handshake(
            ip, hostname, port, timeout, _legacy_context(verify=False)
        )
    except (OSError, TimeoutError) as exc:  # ssl.SSLError is an OSError
        logger.debug("Unverified TLS fallback failed for %s: %s", hostname, exc)
        return None
    return _cert_info(hostname, version, cert_dict, der, False, verify_error, now_utc)
