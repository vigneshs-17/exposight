"""Exceptions and error classification for Exposight worker."""

from asm.discovery import DiscoveryError
from asm.scan_common import ReportValidationError
from asm.validators import DomainValidationError


class SecurityGateError(Exception):
    """Raised when target domain authorization is missing or revoked.

    This is a terminal security error; the scan run fails immediately and is never retried.
    """

    pass


class LostLeaseError(Exception):
    """Raised when a worker detects that it has lost its active job lease or fencing token."""

    pass


# Explicit tuple of expected scanner domain errors.
# If a stage encounters an error in this tuple, that stage fails cleanly,
# stage dependency rules apply, and the overall job is NOT retried.
# Any exception NOT in this tuple is treated as an unexpected worker exception.
EXPECTED_SCANNER_ERRORS: tuple[type[Exception], ...] = (
    DiscoveryError,
    DomainValidationError,
    ReportValidationError,
    SecurityGateError,
)
