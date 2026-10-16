"""Certificate Transparency log discovery via crt.sh with Cert Spotter fallback.

Queries Certificate Transparency logs to passively discover subdomains that have
had TLS/SSL certificates issued for a target domain.

Operational bounds:
- Enforces HTTP streaming response byte limits (Content-Length check & chunked streaming cap).
- Rejects unexpected non-identity Content-Encoding before consuming/decompressing bodies.
- Accounts for cumulative wire transfer across pages, retries, and error bodies.
- Enforces deterministic, in-scope hostname caps with apex prioritization when present.
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

# Operational wire ingestion limits (provisional defaults, overridable via environment)
DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB raw response cap
DEFAULT_MAX_CERTSPOTTER_TOTAL_BYTES = 10 * 1024 * 1024  # 10 MiB cumulative cap
DEFAULT_MAX_CERTSPOTTER_PAGE_BYTES = 2 * 1024 * 1024  # 2 MiB per page
DEFAULT_MAX_HOSTS = 1000  # Maximum unique in-scope hostnames queued for scanning

REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json",
    "Accept-Encoding": "identity",
}


class DiscoveryError(Exception):
    """Base exception for all passive discovery errors."""

    pass


class DiscoveryConfigurationError(DiscoveryError):
    """Raised when discovery configuration or operational limits are invalid."""

    pass


class CrtshError(DiscoveryError):
    """Raised when querying crt.sh fails after exhausting retries or on non-retryable error."""

    pass


class CertSpotterError(DiscoveryError):
    """Raised when querying Cert Spotter fails, exceeds rate limits, or breaches byte limits."""

    pass


class AllSourcesFailedError(DiscoveryError):
    """Raised when both primary (crt.sh) and fallback (Cert Spotter) discovery fail."""

    def __init__(self, message: str, crtsh_error: str, certspotter_error: str) -> None:
        super().__init__(message)
        self.crtsh_error = crtsh_error
        self.certspotter_error = certspotter_error


def _validate_positive_int(value: Any, name: str) -> None:
    """Validate that an operational limit is a positive integer > 0.

    Rejects strings, floats, booleans, and non-positive integers,
    producing DiscoveryConfigurationError rather than incidental TypeError.
    Preserves None where callers use it to indicate default.
    """
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise DiscoveryConfigurationError(
            f"{name} must be a positive integer > 0 (got {value!r})"
        )


def get_discovery_max_response_bytes() -> int:
    """Return validated maximum response bytes for CT providers, or 10 MiB default."""
    raw = os.getenv("DISCOVERY_MAX_RESPONSE_BYTES")
    if raw is None or not raw.strip():
        return DEFAULT_MAX_RESPONSE_BYTES
    raw_str = raw.strip()
    try:
        val = int(raw_str)
        if val <= 0:
            raise DiscoveryConfigurationError(
                f"Invalid DISCOVERY_MAX_RESPONSE_BYTES={raw_str!r}: must be a positive integer > 0"
            )
        return val
    except ValueError as exc:
        raise DiscoveryConfigurationError(
            f"Invalid DISCOVERY_MAX_RESPONSE_BYTES={raw_str!r}: must be a valid integer"
        ) from exc


def get_discovery_max_hosts() -> int:
    """Return validated maximum unique discovered hostnames, or 1000 default."""
    raw = os.getenv("DISCOVERY_MAX_HOSTS")
    if raw is None or not raw.strip():
        return DEFAULT_MAX_HOSTS
    raw_str = raw.strip()
    try:
        val = int(raw_str)
        if val <= 0:
            raise DiscoveryConfigurationError(
                f"Invalid DISCOVERY_MAX_HOSTS={raw_str!r}: must be a positive integer > 0"
            )
        return val
    except ValueError as exc:
        raise DiscoveryConfigurationError(
            f"Invalid DISCOVERY_MAX_HOSTS={raw_str!r}: must be a valid integer"
        ) from exc


class DiscoveryOutcome(tuple):
    """4-tuple subclass (subdomains, source, fallback_reason, truncated) with metadata."""

    subdomains: list[str]
    source: str
    fallback_reason: str | None
    truncated: bool
    truncation_reason: str | None
    observed_count: int

    def __new__(
        cls,
        subdomains: list[str],
        source: str,
        fallback_reason: str | None,
        truncated: bool,
        truncation_reason: str | None = None,
        observed_count: int = 0,
    ) -> DiscoveryOutcome:
        instance = super().__new__(cls, (subdomains, source, fallback_reason, truncated))
        instance.subdomains = subdomains
        instance.source = source
        instance.fallback_reason = fallback_reason
        instance.truncated = truncated
        instance.truncation_reason = truncation_reason
        instance.observed_count = observed_count
        return instance


class CumulativeBudget:
    """Tracks cumulative application-consumed response-body bytes across attempts."""

    def __init__(self, max_total_bytes: int):
        self.max_total_bytes = max_total_bytes
        self.consumed_bytes = 0

    def remaining(self) -> int:
        return max(0, self.max_total_bytes - self.consumed_bytes)

    def charge(self, num_bytes: int, provider_name: str) -> None:
        self.consumed_bytes += num_bytes
        if self.consumed_bytes > self.max_total_bytes:
            raise CertSpotterError(
                f"{provider_name} cumulative transfer exceeded budget of "
                f"{self.max_total_bytes} bytes across attempts (consumed at least "
                f"{self.consumed_bytes} bytes)"
            )


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


def _check_content_encoding(response: httpx.Response, provider_name: str) -> None:
    """Validate that Content-Encoding is identity (or omitted). Reject compressed responses."""
    encoding = response.headers.get("content-encoding", "").strip().lower()
    if encoding and encoding != "identity":
        response.close()
        err_msg = (
            f"{provider_name} returned unexpected Content-Encoding '{encoding}'; "
            "non-identity encoding rejected"
        )
        if provider_name == "crt.sh":
            raise CrtshError(err_msg)
        raise CertSpotterError(err_msg)


def _read_error_text_bounded(
    response: httpx.Response,
    provider_name: str,
    max_bytes: int = 8192,
    budget: CumulativeBudget | None = None,
) -> tuple[str, int]:
    """Safely read bounded error body without decompressing or buffering oversized payloads.

    Charges each chunk to budget as consumed, preserving accounting if iteration raises.
    Retains and decodes only up to max_bytes for the text preview even if the transport
    yields a single chunk larger than max_bytes.
    """
    _check_content_encoding(response, provider_name)
    chunks: list[bytes] = []
    total_bytes = 0
    retained_bytes = 0
    try:
        for chunk in response.iter_bytes(chunk_size=None):
            if not chunk:
                continue
            chunk_len = len(chunk)
            total_bytes += chunk_len
            if budget is not None:
                budget.charge(chunk_len, provider_name)

            needed = max_bytes - retained_bytes
            if needed > 0:
                slice_to_keep = chunk[:needed]
                chunks.append(slice_to_keep)
                retained_bytes += len(slice_to_keep)

            if total_bytes >= max_bytes:
                break
        text_preview = b"".join(chunks).decode("utf-8", errors="replace")[:200]
        return text_preview, total_bytes
    finally:
        response.close()


def _read_response_body_capped(
    response: httpx.Response,
    max_bytes: int,
    provider_name: str,
    budget: CumulativeBudget | None = None,
) -> tuple[bytes, int]:
    """Stream and buffer up to max_bytes from an HTTP response.

    Enforces Content-Length header checks when present, streams chunks to bound
    application-consumed response-body bytes. Note: with chunk_size=None, a transport chunk
    is determined by transport framing/buffers, not an application-defined numeric constant.
    Charges each chunk to budget as consumed, rejects oversized responses without retaining
    oversized chunks in memory, and guarantees response closure.
    """
    _check_content_encoding(response, provider_name)

    cl_str = response.headers.get("content-length")
    if cl_str is not None:
        try:
            cl_val = int(cl_str)
            if cl_val > max_bytes:
                response.close()
                err_msg = (
                    f"{provider_name} response Content-Length ({cl_val} bytes) "
                    f"exceeds limit ({max_bytes} bytes)"
                )
                if provider_name == "crt.sh":
                    raise CrtshError(err_msg)
                raise CertSpotterError(err_msg)
        except ValueError:
            pass

    chunks: list[bytes] = []
    total_bytes = 0
    try:
        for chunk in response.iter_bytes(chunk_size=None):
            if not chunk:
                continue
            chunk_len = len(chunk)
            total_bytes += chunk_len
            if budget is not None:
                budget.charge(chunk_len, provider_name)
            if total_bytes > max_bytes:
                response.close()
                err_msg = (
                    f"{provider_name} response exceeded limit of {max_bytes} bytes "
                    f"(read at least {total_bytes} bytes)"
                )
                if provider_name == "crt.sh":
                    raise CrtshError(err_msg)
                raise CertSpotterError(err_msg)
            chunks.append(chunk)
        return b"".join(chunks), total_bytes
    finally:
        response.close()


def fetch_crtsh_data(
    domain: str,
    client: httpx.Client | None = None,
    max_bytes: int | None = None,
) -> list[dict[str, Any]]:
    """Query crt.sh for certificate logs associated with the given domain.

    Includes retry logic with backoff for transient issues:
    - Retries on network timeouts, connection errors, HTTP 5xx, HTTP 429,
      and invalid JSON responses.
    - Fails immediately on HTTP 4xx client errors, non-identity Content-Encoding,
      or responses exceeding byte budgets.
    - Maximum 3 attempts with 1s and 2s delays between attempts.

    Args:
        domain: The target domain to query (e.g. 'example.com').
        client: Optional httpx.Client instance (useful for unit testing/mocking).
        max_bytes: Optional raw response byte limit (defaults to DISCOVERY_MAX_RESPONSE_BYTES).

    Returns:
        A list of dictionary records returned by crt.sh.

    Raises:
        CrtshError: If all retry attempts fail or non-retryable error occurs.
    """
    _validate_positive_int(max_bytes, "max_bytes")
    effective_max_bytes = (
        max_bytes if max_bytes is not None else get_discovery_max_response_bytes()
    )
    params = {
        "q": f"%.{domain}",
        "output": "json",
    }
    headers = dict(REQUEST_HEADERS)

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
                with active_client.stream(
                    "GET", CRTSH_BASE_URL, params=params, headers=headers
                ) as response:
                    # Validate non-identity Content-Encoding before consuming body on any status
                    _check_content_encoding(response, "crt.sh")

                    # Handle 4xx Client Errors
                    if 400 <= response.status_code < 500:
                        if response.status_code == 429:
                            last_error = "Rate limited (HTTP 429) by crt.sh"
                            logger.warning(
                                "crt.sh returned HTTP 429 Too Many Requests on attempt %d/%d",
                                attempt,
                                MAX_ATTEMPTS,
                            )
                            _ = _read_error_text_bounded(
                                response, "crt.sh", max_bytes=min(8192, effective_max_bytes)
                            )
                        else:
                            truncated_text, _ = _read_error_text_bounded(
                                response, "crt.sh", max_bytes=min(8192, effective_max_bytes)
                            )
                            raise CrtshError(
                                f"crt.sh returned client error HTTP {response.status_code}: "
                                f"{truncated_text}"
                            )
                    # Handle 5xx Server Errors (retryable)
                    elif response.status_code >= 500:
                        _ = _read_error_text_bounded(
                            response, "crt.sh", max_bytes=min(8192, effective_max_bytes)
                        )
                        last_error = f"Server error HTTP {response.status_code} from crt.sh"
                        logger.warning(
                            "crt.sh returned HTTP %d on attempt %d/%d",
                            response.status_code,
                            attempt,
                            MAX_ATTEMPTS,
                        )
                    else:
                        body_bytes, _ = _read_response_body_capped(
                            response, max_bytes=effective_max_bytes, provider_name="crt.sh"
                        )
                        try:
                            data = json.loads(body_bytes.decode("utf-8"))
                            if isinstance(data, list):
                                return data
                            last_error = (
                                f"Unexpected JSON structure from crt.sh: "
                                f"expected list, got {type(data).__name__}"
                            )
                            logger.warning(
                                "crt.sh returned unexpected JSON structure on attempt %d/%d",
                                attempt,
                                MAX_ATTEMPTS,
                            )
                        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
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
            except httpx.TransportError as exc:
                last_error = f"Network connection error: {exc}"
                logger.warning(
                    "Network error querying crt.sh on attempt %d/%d: %s",
                    attempt,
                    MAX_ATTEMPTS,
                    exc,
                )

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

            if cleaned.startswith("*."):
                cleaned = cleaned[2:]
            elif cleaned.startswith("*"):
                cleaned = cleaned[1:]

            cleaned = cleaned.strip(".")

            if not _is_valid_discovered_name(cleaned):
                continue

            if cleaned == normalized_target or cleaned.endswith(scope_suffix):
                unique_subdomains.add(cleaned)

    return sorted(unique_subdomains)


def _fetch_certspotter_page(
    active_client: httpx.Client,
    params: dict[str, str],
    headers: dict[str, str],
    domain: str,
    max_page_bytes: int,
    budget: CumulativeBudget,
) -> list[dict[str, Any]]:
    """Fetch a page from Cert Spotter with Retry-After backoff and cumulative budgeting."""
    last_error = "Unknown error"
    retried_429 = False

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            with active_client.stream(
                "GET", CERTSPOTTER_BASE_URL, params=params, headers=headers
            ) as response:
                # 1. Enforce non-identity Content-Encoding before consuming ANY body on EVERY status
                _check_content_encoding(response, "Cert Spotter")

                # 2. Check remaining cumulative budget
                remaining = budget.remaining()
                if remaining <= 0:
                    raise CertSpotterError(
                        "Cert Spotter cumulative transfer exceeded budget of "
                        f"{budget.max_total_bytes} bytes across attempts"
                    )
                effective_limit = min(max_page_bytes, remaining)

                if response.status_code == 429:
                    retry_after_str = response.headers.get("Retry-After")
                    try:
                        retry_after_sec = float(retry_after_str) if retry_after_str else None
                    except (ValueError, TypeError):
                        retry_after_sec = None

                    _read_error_text_bounded(
                        response,
                        "Cert Spotter",
                        max_bytes=min(8192, effective_limit),
                        budget=budget,
                    )

                    if not retried_429:
                        if retry_after_sec is not None and 0 <= retry_after_sec <= 10.0:
                            logger.warning(
                                "Cert Spotter returned HTTP 429 with Retry-After=%.1fs; "
                                "retrying once",
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
                    truncated_text, _ = _read_error_text_bounded(
                        response,
                        "Cert Spotter",
                        max_bytes=min(8192, effective_limit),
                        budget=budget,
                    )
                    raise CertSpotterError(
                        f"Cert Spotter returned client error HTTP {response.status_code}: "
                        f"{truncated_text}"
                    )
                elif response.status_code >= 500:
                    _read_error_text_bounded(
                        response,
                        "Cert Spotter",
                        max_bytes=min(8192, effective_limit),
                        budget=budget,
                    )
                    last_error = f"Server error HTTP {response.status_code} from Cert Spotter"
                    logger.warning(
                        "Cert Spotter returned HTTP %d on attempt %d/%d",
                        response.status_code,
                        attempt,
                        MAX_ATTEMPTS,
                    )
                else:
                    body_bytes, _ = _read_response_body_capped(
                        response,
                        max_bytes=effective_limit,
                        provider_name="Cert Spotter",
                        budget=budget,
                    )
                    try:
                        data = json.loads(body_bytes.decode("utf-8"))
                        if isinstance(data, list):
                            return data
                        last_error = (
                            f"Unexpected JSON structure from Cert Spotter: "
                            f"expected list, got {type(data).__name__}"
                        )
                    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                        last_error = f"Failed to parse JSON response from Cert Spotter: {exc}"

        except httpx.TimeoutException as exc:
            last_error = f"Connection timed out: {exc}"
            logger.warning(
                "Timeout querying Cert Spotter on attempt %d/%d: %s",
                attempt,
                MAX_ATTEMPTS,
                exc,
            )
        except httpx.TransportError as exc:
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
    max_total_bytes: int = DEFAULT_MAX_CERTSPOTTER_TOTAL_BYTES,
    max_page_bytes: int = DEFAULT_MAX_CERTSPOTTER_PAGE_BYTES,
) -> tuple[list[dict[str, Any]], bool]:
    """Query Cert Spotter API with pagination, rate limiting, and bounding.

    Enforces both per-page and cumulative wire transfer budgets across pages,
    retries, and error bodies.

    Args:
        domain: Normalized target domain.
        client: Optional httpx.Client instance for testing.
        api_key: Optional API key. If not passed, checks CERTSPOTTER_API_KEY env var.
        max_pages: Maximum pagination pages to retrieve (default: 10).
        max_entries: Maximum raw issuance entries to collect (default: 5000).
        max_total_bytes: Maximum cumulative response bytes across all pages (default: 10 MiB).
        max_page_bytes: Maximum bytes allowed for any single page response (default: 2 MiB).

    Returns:
        tuple of (entries, truncated):
        - entries: List of raw issuance dictionaries from Cert Spotter.
        - truncated: True if page limit or entry limit halted pagination, False otherwise.

    Raises:
        CertSpotterError: If API limits, rate limits, or byte limits are exceeded.
    """
    _validate_positive_int(max_pages, "max_pages")
    _validate_positive_int(max_entries, "max_entries")
    _validate_positive_int(max_total_bytes, "max_total_bytes")
    _validate_positive_int(max_page_bytes, "max_page_bytes")

    api_key_to_use = api_key or os.environ.get("CERTSPOTTER_API_KEY")
    headers = dict(REQUEST_HEADERS)
    if api_key_to_use:
        headers["Authorization"] = f"Bearer {api_key_to_use}"

    owns_client = client is None
    active_client = client if client is not None else httpx.Client(timeout=REQUEST_TIMEOUT)

    collected_entries: list[dict[str, Any]] = []
    truncated = False
    last_id: str | int | None = None
    budget = CumulativeBudget(max_total_bytes=max_total_bytes)

    try:
        for page in range(1, max_pages + 1):
            if budget.remaining() <= 0:
                raise CertSpotterError(
                    "Cert Spotter cumulative transfer exceeded budget of "
                    f"{max_total_bytes} bytes across pages"
                )

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
                max_page_bytes=max_page_bytes,
                budget=budget,
            )

            if not page_data:
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


def select_bounded_subdomains(
    unique_subdomains: list[str] | set[str],
    target_domain: str,
    max_hosts: int,
) -> tuple[list[str], bool, int]:
    """Deterministically select up to max_hosts subdomains.

    Rules:
    - Normalizes target_domain.
    - If target_domain (apex) is present in unique_subdomains, it is prioritized at index 0.
      The apex is NEVER added if not present in unique_subdomains.
    - Remaining unique subdomains (excluding apex) are sorted lexicographically.
    - Selects up to max_hosts total names:
      - If apex present and max_hosts > 0: [apex] + remaining[:max_hosts - 1]
      - Else: remaining[:max_hosts]
    - Truncation is True ONLY if total unique hostnames > max_hosts.
      If exactly max_hosts names were discovered, truncated is False because no names were excluded.

    Returns:
        tuple of (selected_subdomains, hostname_truncated, observed_count)
    """
    _validate_positive_int(max_hosts, "max_hosts")
    normalized_target = target_domain.lower().strip(".")
    unique_set = {s.lower().strip(".") for s in unique_subdomains if s}
    observed_count = len(unique_set)

    apex_present = normalized_target in unique_set
    remaining_sorted = sorted(s for s in unique_set if s != normalized_target)

    if apex_present:
        selected = [normalized_target] + remaining_sorted[: max_hosts - 1]
    else:
        selected = remaining_sorted[:max_hosts]

    hostname_truncated = observed_count > max_hosts
    return selected, hostname_truncated, observed_count


def discover_subdomains(
    domain: str,
    client: httpx.Client | None = None,
    api_key: str | None = None,
    crtsh_fetcher: Any | None = None,
    max_hosts: int | None = None,
    max_response_bytes: int | None = None,
) -> DiscoveryOutcome:
    """Execute passive subdomain discovery using crt.sh with Cert Spotter fallback.

    Enforces streaming byte caps and deterministic hostname capping.

    Returns:
        DiscoveryOutcome (subdomains, source, fallback_reason, truncated)
        - subdomains: bounded unique in-scope subdomains (apex prioritized if found)
        - source: 'crt.sh' or 'certspotter'
        - fallback_reason: None if crt.sh succeeded, or sanitized crt.sh failure reason
        - truncated: True if provider limits OR hostname cap was exceeded
        - outcome.truncation_reason: 'hostname_cap_exceeded', 'provider_entry_limit',
          'provider_and_hostname_cap_exceeded', or None
        - outcome.observed_count: count of unique in-scope hostnames observed before capping
    """
    _validate_positive_int(max_hosts, "max_hosts")
    _validate_positive_int(max_response_bytes, "max_response_bytes")

    effective_max_hosts = (
        max_hosts if max_hosts is not None else get_discovery_max_hosts()
    )
    effective_max_bytes = (
        max_response_bytes
        if max_response_bytes is not None
        else get_discovery_max_response_bytes()
    )

    fetcher = crtsh_fetcher or fetch_crtsh_data
    try:
        try:
            crtsh_entries = fetcher(domain, client=client, max_bytes=effective_max_bytes)
        except TypeError:
            crtsh_entries = fetcher(domain, client=client)

        parsed_subdomains = parse_subdomains(crtsh_entries, domain)
        selected, hostname_truncated, observed_count = select_bounded_subdomains(
            parsed_subdomains, domain, effective_max_hosts
        )
        provider_truncated = False
        truncated = provider_truncated or hostname_truncated
        truncation_reason = "hostname_cap_exceeded" if hostname_truncated else None

        return DiscoveryOutcome(
            subdomains=selected,
            source="crt.sh",
            fallback_reason=None,
            truncated=truncated,
            truncation_reason=truncation_reason,
            observed_count=observed_count,
        )
    except CrtshError as crtsh_exc:
        from asm.scan_common import sanitize_error_text

        fallback_reason = sanitize_error_text(str(crtsh_exc), max_length=300)
        logger.warning(
            "Primary discovery via crt.sh failed for '%s': %s; engaging Cert Spotter fallback",
            domain,
            fallback_reason,
        )
        try:
            cs_entries, provider_truncated = fetch_certspotter_data(
                domain,
                client=client,
                api_key=api_key,
                max_total_bytes=effective_max_bytes,
            )
            adapted_records = transform_certspotter_to_raw_records(cs_entries)
            parsed_subdomains = parse_subdomains(adapted_records, domain)
            selected, hostname_truncated, observed_count = select_bounded_subdomains(
                parsed_subdomains, domain, effective_max_hosts
            )
            truncated = provider_truncated or hostname_truncated
            if provider_truncated and hostname_truncated:
                truncation_reason = "provider_and_hostname_cap_exceeded"
            elif hostname_truncated:
                truncation_reason = "hostname_cap_exceeded"
            elif provider_truncated:
                truncation_reason = "provider_entry_limit"
            else:
                truncation_reason = None

            return DiscoveryOutcome(
                subdomains=selected,
                source="certspotter",
                fallback_reason=fallback_reason,
                truncated=truncated,
                truncation_reason=truncation_reason,
                observed_count=observed_count,
            )
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
