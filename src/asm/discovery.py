"""Certificate Transparency log discovery via crt.sh.

Queries crt.sh to passively discover subdomains that have had TLS/SSL
certificates issued for a target domain.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

CRTSH_BASE_URL = "https://crt.sh"
CERTSPOTTER_BASE_URL = "https://api.certspotter.com/v1/issuances"
USER_AGENT = "Exposight/0.1 (+https://github.com/vigneshs-17/exposight)"
REQUEST_TIMEOUT = 30.0
MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = [1, 2]  # Wait 1s after attempt 1, 2s after attempt 2
MAX_CERTSPOTTER_PAGES = 10
MAX_CERTSPOTTER_ENTRIES = 5000


class DiscoveryError(Exception):
    """Base exception for all passive discovery errors."""

    pass


class CrtshError(DiscoveryError):
    """Raised when querying crt.sh fails after exhausting all retries."""

    pass


class CertSpotterError(DiscoveryError):
    """Raised when querying Cert Spotter fails or exceeds rate limits."""

    pass


class AllSourcesFailedError(DiscoveryError):
    """Raised when both primary (crt.sh) and fallback (Cert Spotter) discovery fail."""

    def __init__(self, message: str, crtsh_error: str, certspotter_error: str) -> None:
        super().__init__(message)
        self.crtsh_error = crtsh_error
        self.certspotter_error = certspotter_error


def _is_valid_discovered_name(candidate: str) -> bool:
    """Check if a discovered name is a syntactically valid hostname.

    Filters out certificate common names that are emails, IP addresses,
    or contain invalid DNS characters.

    Args:
        candidate: The sanitized hostname candidate.

    Returns:
        True if candidate is a valid DNS hostname, False otherwise.
    """
    if not candidate or len(candidate) > 253 or "@" in candidate:
        return False

    # Disallow whitespace or invalid characters
    label_pattern = re.compile(r"^[a-z0-9-]+$")
    labels = candidate.split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not label_pattern.match(label):
            return False

    return True


def fetch_crtsh_data(domain: str, client: httpx.Client | None = None) -> list[dict[str, Any]]:
    """Query crt.sh for certificate logs associated with the given domain.

    Includes retry logic with backoff for transient issues:
    - Retries on network timeouts, connection errors, HTTP 5xx, HTTP 429,
      and invalid JSON responses.
    - Fails immediately on other HTTP 4xx client errors.
    - Maximum 3 attempts with 1s and 2s delays between attempts.

    Args:
        domain: The target domain to query (e.g. 'example.com').
        client: Optional httpx.Client instance (useful for unit testing/mocking).

    Returns:
        A list of dictionary records returned by crt.sh.

    Raises:
        CrtshError: If all retry attempts fail or a non-retryable 4xx is returned.
    """
    params = {
        "q": f"%.{domain}",
        "output": "json",
    }
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    # Use provided client or create a short-lived local client
    owns_client = client is None
    active_client = client if client is not None else httpx.Client(timeout=REQUEST_TIMEOUT)

    last_error: str = "Unknown error"

    try:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            logger.debug(
                "Querying crt.sh for domain '%s' (Attempt %d/%d)",
                domain,
                attempt,
                MAX_ATTEMPTS,
            )
            try:
                response = active_client.get(CRTSH_BASE_URL, params=params, headers=headers)

                # Handle 4xx Client Errors
                if 400 <= response.status_code < 500:
                    if response.status_code == 429:
                        # Rate limited: retryable
                        last_error = "Rate limited (HTTP 429) by crt.sh"
                        logger.warning(
                            "crt.sh returned HTTP 429 Too Many Requests on attempt %d/%d",
                            attempt,
                            MAX_ATTEMPTS,
                        )
                    else:
                        # Non-retryable 4xx error (e.g. 400 Bad Request, 404 Not Found)
                        truncated_text = response.text[:200]
                        raise CrtshError(
                            f"crt.sh returned client error HTTP {response.status_code}: "
                            f"{truncated_text}"
                        )
                # Handle 5xx Server Errors (retryable)
                elif response.status_code >= 500:
                    last_error = f"Server error HTTP {response.status_code} from crt.sh"
                    logger.warning(
                        "crt.sh returned HTTP %d on attempt %d/%d",
                        response.status_code,
                        attempt,
                        MAX_ATTEMPTS,
                    )
                else:
                    # Successful HTTP status code; attempt JSON decoding
                    try:
                        data = response.json()
                        if isinstance(data, list):
                            return data
                        # crt.sh occasionally returns JSON error payloads or unexpected types
                        last_error = (
                            f"Unexpected JSON structure from crt.sh: "
                            f"expected list, got {type(data).__name__}"
                        )
                        logger.warning(
                            "crt.sh returned unexpected JSON structure on attempt %d/%d",
                            attempt,
                            MAX_ATTEMPTS,
                        )
                    except (json.JSONDecodeError, ValueError) as exc:
                        last_error = f"Failed to parse JSON response: {exc}"
                        logger.warning(
                            "crt.sh returned non-JSON response on attempt %d/%d: %s",
                            attempt,
                            MAX_ATTEMPTS,
                            exc,
                        )

            except httpx.TimeoutException as exc:
                last_error = f"Connection timed out: {exc}"
                logger.warning(
                    "Timeout querying crt.sh on attempt %d/%d: %s",
                    attempt,
                    MAX_ATTEMPTS,
                    exc,
                )
            except httpx.NetworkError as exc:
                last_error = f"Network connection error: {exc}"
                logger.warning(
                    "Network error querying crt.sh on attempt %d/%d: %s",
                    attempt,
                    MAX_ATTEMPTS,
                    exc,
                )

            # If there are attempts remaining, pause before the next attempt
            if attempt < MAX_ATTEMPTS:
                wait_time = RETRY_BACKOFF_SECONDS[attempt - 1]
                logger.debug("Waiting %ds before retry...", wait_time)
                time.sleep(wait_time)

    finally:
        if owns_client:
            active_client.close()

    # All retries exhausted
    raise CrtshError(
        f"Failed to retrieve data from crt.sh after {MAX_ATTEMPTS} attempts. "
        f"Last error: {last_error}"
    )


def parse_subdomains(crtsh_entries: list[dict[str, Any]], target_domain: str) -> list[str]:
    """Parse and clean subdomains from raw crt.sh records.

    Rules applied:
    - Splits multi-line 'name_value' fields.
    - Converts all names to lowercase.
    - Strips leading wildcard prefixes (e.g. '*.' or '*').
    - Discards invalid hostnames (emails, IP addresses, invalid characters).
    - Discards out-of-scope hostnames (must equal target_domain or end with '.<target_domain>').
    - Deduplicates and returns an alphabetically sorted list.

    Args:
        crtsh_entries: List of records returned from crt.sh JSON output.
        target_domain: The domain being searched (e.g. 'example.com').

    Returns:
        Sorted list of unique discovered subdomains.
    """
    normalized_target = target_domain.lower().strip(".")
    scope_suffix = f".{normalized_target}"
    unique_subdomains: set[str] = set()

    for entry in crtsh_entries:
        name_value = entry.get("name_value")
        if not name_value or not isinstance(name_value, str):
            continue

        for line in name_value.splitlines():
            cleaned = line.strip().lower()

            # Remove leading wildcard syntax (e.g. '*.sub.example.com' -> 'sub.example.com')
            if cleaned.startswith("*."):
                cleaned = cleaned[2:]
            elif cleaned.startswith("*"):
                cleaned = cleaned[1:]

            cleaned = cleaned.strip(".")

            # Validate syntax and filter out invalid names (e.g. emails)
            if not _is_valid_discovered_name(cleaned):
                continue

            # Scope check: must be target_domain or end with .target_domain
            if cleaned == normalized_target or cleaned.endswith(scope_suffix):
                unique_subdomains.add(cleaned)

    return sorted(unique_subdomains)


def _fetch_certspotter_page(
    active_client: httpx.Client,
    params: dict[str, str],
    headers: dict[str, str],
    domain: str,
) -> list[dict[str, Any]]:
    """Fetch a single page from Cert Spotter API with 429 Retry-After and 5xx backoff handling."""
    last_error = "Unknown error"
    retried_429 = False

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = active_client.get(CERTSPOTTER_BASE_URL, params=params, headers=headers)

            if response.status_code == 429:
                if not retried_429:
                    retry_after_str = response.headers.get("Retry-After")
                    try:
                        retry_after_sec = float(retry_after_str) if retry_after_str else None
                    except (ValueError, TypeError):
                        retry_after_sec = None

                    if retry_after_sec is not None and 0 <= retry_after_sec <= 10.0:
                        logger.warning(
                            "Cert Spotter returned HTTP 429 with Retry-After=%.1fs; retrying once",
                            retry_after_sec,
                        )
                        time.sleep(retry_after_sec)
                        retried_429 = True
                        continue
                    else:
                        raise CertSpotterError(
                            "Cert Spotter rate limited (HTTP 429) with "
                            f"Retry-After={retry_after_str}"
                        )
                else:
                    raise CertSpotterError("Cert Spotter rate limited (HTTP 429) after retry")

            elif 400 <= response.status_code < 500:
                raise CertSpotterError(
                    f"Cert Spotter returned client error HTTP {response.status_code}: "
                    f"{response.text[:200]}"
                )
            elif response.status_code >= 500:
                last_error = f"Server error HTTP {response.status_code} from Cert Spotter"
                logger.warning(
                    "Cert Spotter returned HTTP %d on attempt %d/%d",
                    response.status_code,
                    attempt,
                    MAX_ATTEMPTS,
                )
            else:
                try:
                    data = response.json()
                    if isinstance(data, list):
                        return data
                    last_error = (
                        f"Unexpected JSON structure from Cert Spotter: "
                        f"expected list, got {type(data).__name__}"
                    )
                except (json.JSONDecodeError, ValueError) as exc:
                    last_error = f"Failed to parse JSON response from Cert Spotter: {exc}"

        except httpx.TimeoutException as exc:
            last_error = f"Connection timed out: {exc}"
            logger.warning(
                "Timeout querying Cert Spotter on attempt %d/%d: %s",
                attempt,
                MAX_ATTEMPTS,
                exc,
            )
        except httpx.NetworkError as exc:
            last_error = f"Network connection error: {exc}"
            logger.warning(
                "Network error querying Cert Spotter on attempt %d/%d: %s",
                attempt,
                MAX_ATTEMPTS,
                exc,
            )

        if attempt < MAX_ATTEMPTS:
            wait_time = RETRY_BACKOFF_SECONDS[attempt - 1]
            time.sleep(wait_time)

    raise CertSpotterError(
        f"Failed to retrieve data from Cert Spotter after {MAX_ATTEMPTS} attempts. "
        f"Last error: {last_error}"
    )


def fetch_certspotter_data(
    domain: str,
    client: httpx.Client | None = None,
    api_key: str | None = None,
    max_pages: int = MAX_CERTSPOTTER_PAGES,
    max_entries: int = MAX_CERTSPOTTER_ENTRIES,
) -> tuple[list[dict[str, Any]], bool]:
    """Query Cert Spotter API with pagination, rate limiting, and bounding.

    Args:
        domain: Normalized target domain.
        client: Optional httpx.Client instance for testing.
        api_key: Optional API key. If not passed, checks CERTSPOTTER_API_KEY env var.
        max_pages: Maximum pagination pages to retrieve (default: 10).
        max_entries: Maximum raw issuance entries to collect (default: 5000).

    Returns:
        tuple of (entries, truncated):
        - entries: List of raw issuance dictionaries from Cert Spotter.
        - truncated: True if page limit or entry limit halted pagination, False otherwise.

    Raises:
        CertSpotterError: If API limits are exceeded or unrecoverable HTTP errors occur.
    """
    api_key_to_use = api_key or os.environ.get("CERTSPOTTER_API_KEY")
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    if api_key_to_use:
        headers["Authorization"] = f"Bearer {api_key_to_use}"

    owns_client = client is None
    active_client = client if client is not None else httpx.Client(timeout=REQUEST_TIMEOUT)

    collected_entries: list[dict[str, Any]] = []
    truncated = False
    last_id: str | int | None = None

    try:
        for page in range(1, max_pages + 1):
            params: dict[str, str] = {
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            }
            if last_id is not None:
                params["after"] = str(last_id)

            page_data = _fetch_certspotter_page(
                active_client=active_client,
                params=params,
                headers=headers,
                domain=domain,
            )

            if not page_data:
                # Empty array terminates pagination
                break

            for item in page_data:
                collected_entries.append(item)
                if len(collected_entries) >= max_entries:
                    truncated = True
                    break

            if truncated:
                break

            last_id = page_data[-1].get("id")
            if not last_id:
                break

            if page == max_pages:
                truncated = True
                break

    finally:
        if owns_client:
            active_client.close()

    return collected_entries, truncated


def transform_certspotter_to_raw_records(
    certspotter_entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Transform Cert Spotter dns_names lists into crt.sh-compatible name_value records."""
    records: list[dict[str, Any]] = []
    for entry in certspotter_entries:
        dns_names = entry.get("dns_names")
        if isinstance(dns_names, list):
            valid_names = [name for name in dns_names if isinstance(name, str)]
            if valid_names:
                records.append({"name_value": "\n".join(valid_names)})
    return records


def discover_subdomains(
    domain: str,
    client: httpx.Client | None = None,
    api_key: str | None = None,
    crtsh_fetcher: Any | None = None,
) -> tuple[list[str], str, str | None, bool]:
    """Execute passive subdomain discovery using crt.sh with Cert Spotter fallback.

    Returns:
        tuple of (subdomains, source, fallback_reason, truncated)
        - subdomains: sorted unique list of in-scope subdomains
        - source: 'crt.sh' or 'certspotter'
        - fallback_reason: None if crt.sh succeeded, or sanitized crt.sh failure reason
        - truncated: False for crt.sh; True if Cert Spotter was capped by max pages/entries
    """
    fetcher = crtsh_fetcher or fetch_crtsh_data
    try:
        crtsh_entries = fetcher(domain, client=client)
        subdomains = parse_subdomains(crtsh_entries, domain)
        return subdomains, "crt.sh", None, False
    except CrtshError as crtsh_exc:
        from asm.scan_common import sanitize_error_text

        fallback_reason = sanitize_error_text(str(crtsh_exc), max_length=300)
        logger.warning(
            "Primary discovery via crt.sh failed for '%s': %s; engaging Cert Spotter fallback",
            domain,
            fallback_reason,
        )
        try:
            cs_entries, truncated = fetch_certspotter_data(domain, client=client, api_key=api_key)
            adapted_records = transform_certspotter_to_raw_records(cs_entries)
            subdomains = parse_subdomains(adapted_records, domain)
            return subdomains, "certspotter", fallback_reason, truncated
        except CertSpotterError as cs_exc:
            cs_error_sanitized = sanitize_error_text(str(cs_exc), max_length=300) or str(cs_exc)
            logger.error(
                "Cert Spotter fallback discovery failed for '%s': %s",
                domain,
                cs_error_sanitized,
            )
            crtsh_err_str = fallback_reason or str(crtsh_exc)
            raise AllSourcesFailedError(
                f"Discovery failed across all sources for '{domain}': "
                f"crt.sh error: {crtsh_err_str}; Cert Spotter error: {cs_error_sanitized}",
                crtsh_error=crtsh_err_str,
                certspotter_error=cs_error_sanitized,
            ) from cs_exc
