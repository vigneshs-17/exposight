"""Customer-facing descriptions of stored change records.

Each description states only what the scanner observed. It does not say when or why
an asset changed: a periodic external scan records when Exposight observed a
difference, not when it happened.

Descriptions are keyed by the existing change_type identifiers (and, for
CERTIFICATE_CHANGED, the stored detail). The identifiers, severities and alert rules
are unchanged. Wording must stay true for every stored row of that type, including
rows written by earlier detector versions. Types without an entry here get no
description and display exactly as before.
"""

from __future__ import annotations

# PORT_NO_LONGER_OPEN is emitted only when the port is in the scan's closed_ports, and the
# scanner records CLOSED only for an explicit connection refusal. A timeout or other
# inconclusive connection result is recorded as FILTERED and never produces this change.
CHANGE_DESCRIPTIONS: dict[str, str] = {
    "PORT_NEWLY_OPEN": (
        "This scan observed the port accepting connections. The comparison evidence "
        "did not establish it as open. This does not establish when the service "
        "became reachable."
    ),
    "PORT_REOPENED": "port observed open again after a single closed observation",
    "PORT_OBSERVED_OPEN": (
        "port observed open; no earlier definite observation for comparison"
    ),
    "PORT_NO_LONGER_OPEN": (
        "This port refused the scanner's connection in this scan. An earlier scan "
        "observed it open. This records the scanner's connection result only; it does "
        "not show why the connection was refused."
    ),
    "NEW_SUBDOMAIN": (
        "This name appeared in discovery results outside the current tracked "
        "inventory. It may be newly discovered or previously observed."
    ),
    "REMOVED_SUBDOMAIN": (
        "This name was missing from discovery results compared with earlier scans. "
        "Absence from discovery results does not confirm the name or its services "
        "were deleted."
    ),
    # Verified across all emitting branches (persisted_inventory and bounded history):
    # NEWLY_RESOLVING requires b_stat == "NXDOMAIN" and n_stat == "RESOLVED" and n_res;
    # STOPPED_RESOLVING requires b_stat == "RESOLVED" and b_res and n_stat == "NXDOMAIN"
    # and not n_res. Missing, TIMEOUT, ERROR, and NO_ANSWER baselines never emit either.
    "NEWLY_RESOLVING": (
        "A DNS lookup for this name returned addresses after an earlier compared "
        "lookup returned NXDOMAIN (name does not exist). This does not establish "
        "when the DNS record changed."
    ),
    "STOPPED_RESOLVING": (
        "A DNS lookup for this name returned NXDOMAIN (name does not exist) after an "
        "earlier compared lookup returned addresses. This does not confirm the asset "
        "was deleted."
    ),
}

_CERT_PRESENTED = (
    "This shows a difference in the certificate presented to the scanner; it does not "
    "by itself show why the certificate differs."
)

CERTIFICATE_CHANGED_DESCRIPTIONS: dict[str, str] = {
    "issuer": (
        "The certificate presented to the scanner has a different issuing authority (CA) from the "
        f"certificate recorded in an earlier scan. {_CERT_PRESENTED}"
    ),
    "not_after": (
        "The certificate presented to the scanner has a different expiry date from an "
        f"earlier certificate. {_CERT_PRESENTED}"
    ),
    # Emitted when a TLS problem reported earlier is no longer reported. Current detection
    # also requires affirmative evidence that the check passed; older rows did not, so the
    # wording claims only that the problem was not found.
    "": (
        "A certificate problem reported in an earlier scan was not found on the "
        "certificate presented in this scan."
    ),
}

CERTIFICATE_CHANGED_FALLBACK = (
    "The certificate presented to the scanner differs from one recorded in an earlier "
    f"scan. {_CERT_PRESENTED}"
)


def describe_change(change_type: str | None, detail: str | None = None) -> str:
    """Return the evidence-based description for a change record, or "" if none applies."""
    if not change_type:
        return ""
    if change_type == "CERTIFICATE_CHANGED":
        return CERTIFICATE_CHANGED_DESCRIPTIONS.get(detail or "", CERTIFICATE_CHANGED_FALLBACK)
    return CHANGE_DESCRIPTIONS.get(change_type, "")
