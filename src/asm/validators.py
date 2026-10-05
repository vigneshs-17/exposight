"""Domain validation and normalization module.

This module provides functions to sanitize, normalize, and validate domain
names provided by the user before performing any passive discovery.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse


class DomainValidationError(Exception):
    """Raised when an input cannot be validated as a legitimate domain name."""


def normalize_domain(raw_input: str) -> str:
    """Normalize a raw domain or URL string to a clean, lowercase domain name.

    Steps:
    1. Strip leading and trailing whitespace.
    2. Parse using urllib.parse to handle URLs with schemes, paths, ports, or credentials.
    3. Extract the hostname component (which automatically removes port and userinfo).
    4. Strip any trailing dots (standard DNS representation for root).
    5. Convert to lowercase.

    Examples:
        >>> normalize_domain("  example.COM  ")
        'example.com'
        >>> normalize_domain("http://EXAMPLE.COM:8080/path?arg=1")
        'example.com'
        >>> normalize_domain("sub.example.com.")
        'sub.example.com'

    Args:
        raw_input: The raw string provided by the user.

    Returns:
        The normalized domain string.

    Raises:
        DomainValidationError: If the input cannot be parsed.
    """
    if not raw_input or not raw_input.strip():
        raise DomainValidationError("Domain input cannot be empty.")

    cleaned = raw_input.strip()

    # If the input itself is directly an IP address (IPv4 or IPv6), preserve it
    # so validate_domain can explicitly reject it with a clear error message.
    ip_candidate = cleaned.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(ip_candidate)
        return str(ip_obj)
    except ValueError:
        pass

    # If the user did not include a scheme, prepend '//' so urllib.parse.urlsplit
    # correctly recognizes the authority (netloc) component rather than the path.
    if "://" not in cleaned:
        parse_target = f"//{cleaned}"
    else:
        parse_target = cleaned

    try:
        parsed = urllib.parse.urlsplit(parse_target)
    except Exception as exc:
        raise DomainValidationError(f"Failed to parse domain input: {exc}") from exc

    # urlsplit().hostname extracts the host and automatically converts ASCII to lowercase
    hostname = parsed.hostname

    if not hostname:
        # Fallback: if hostname is None (e.g. invalid URL structure), split on slash and port
        fallback = cleaned.split("/")[0].split(":")[0].strip()
        hostname = fallback.lower()

    # Strip any trailing dot (e.g. "example.com." -> "example.com")
    normalized = hostname.rstrip(".").lower()

    if not normalized:
        raise DomainValidationError("Extracted domain name is empty.")

    return normalized


def validate_domain(raw_input: str) -> str:
    """Validate that the normalized string is a safe, valid domain name.

    Performs the following security and RFC checks:
    - Normalizes the input.
    - Rejects IP addresses (both IPv4 and IPv6).
    - Checks that total length does not exceed 253 characters (RFC 1035).
    - Checks that the domain has at least two labels (e.g., domain + TLD).
    - Ensures each label is between 1 and 63 characters.
    - Ensures labels contain only letters, numbers, and hyphens, and do not
      start or end with a hyphen.
    - Ensures the Top-Level Domain (TLD) is not purely numeric.

    Args:
        raw_input: The raw domain or URL string to validate.

    Returns:
        The validated and normalized domain name.

    Raises:
        DomainValidationError: If validation fails.
    """
    domain = normalize_domain(raw_input)

    # 1. Reject IP addresses (IPv4 and IPv6)
    try:
        ipaddress.ip_address(domain)
        raise DomainValidationError(
            f"'{domain}' is an IP address. Exposight requires a domain name (e.g., example.com)."
        )
    except ValueError:
        # Not an IP address, which is what we want
        pass

    # 2. Total length check (RFC 1035 / RFC 1123 max length is 253 octets)
    if len(domain) > 253:
        raise DomainValidationError(
            f"Domain length ({len(domain)} chars) exceeds the maximum allowed "
            "length of 253 characters."
        )

    # 3. Label count check (must have at least domain + TLD, e.g. example.com)
    labels = domain.split(".")
    if len(labels) < 2:
        raise DomainValidationError(
            f"'{domain}' is not a fully qualified domain name. Must include a domain and a TLD."
        )

    # Regex for valid DNS label characters (letters, digits, hyphens)
    label_pattern = re.compile(r"^[a-z0-9-]+$")

    for label in labels:
        # Empty label check (e.g. consecutive dots like 'example..com')
        if not label:
            raise DomainValidationError(
                f"Domain '{domain}' contains an empty label (e.g. consecutive dots)."
            )

        # Label length check (max 63 octets per RFC 1035)
        if len(label) > 63:
            raise DomainValidationError(
                f"Label '{label}' is {len(label)} characters long, "
                "exceeding the 63 character limit."
            )

        # Hyphen placement rules: cannot start or end with a hyphen
        if label.startswith("-") or label.endswith("-"):
            raise DomainValidationError(
                f"Label '{label}' cannot start or end with a hyphen."
            )

        # Allowed characters check
        if not label_pattern.match(label):
            raise DomainValidationError(
                f"Label '{label}' contains invalid characters. "
                "Only alphanumeric characters and hyphens are allowed."
            )

    # 4. TLD check: the last label must not be purely numeric
    tld = labels[-1]
    if tld.isdigit():
        raise DomainValidationError(
            f"TLD '{tld}' cannot be purely numeric."
        )

    return domain
