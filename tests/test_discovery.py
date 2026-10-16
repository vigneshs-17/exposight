"""Unit tests for Certificate Transparency discovery, resource limits, and encoding checks."""

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from asm.discovery import (
    CRTSH_BASE_URL,
    USER_AGENT,
    AllSourcesFailedError,
    CertSpotterError,
    CrtshError,
    CumulativeBudget,
    DiscoveryConfigurationError,
    DiscoveryError,
    DiscoveryOutcome,
    _fetch_certspotter_page,
    _read_error_text_bounded,
    _validate_positive_int,
    discover_subdomains,
    fetch_certspotter_data,
    fetch_crtsh_data,
    get_discovery_max_hosts,
    get_discovery_max_response_bytes,
    parse_subdomains,
    select_bounded_subdomains,
    transform_certspotter_to_raw_records,
)


class TestSubdomainParsing:
    """Test suite for parse_subdomains using mock and fixture data."""

    def test_parse_subdomains_from_fixture(self, crtsh_sample_data):
        """Verify parsing handles wildcards, newlines, duplicates, emails, and scope."""
        target_domain = "example.com"
        results = parse_subdomains(crtsh_sample_data, target_domain)

        expected = [
            "api.example.com",
            "corp.example.com",
            "dev.example.com",
            "example.com",
            "staging.example.com",
            "vpn.corp.example.com",
        ]
        assert results == expected

    def test_parse_subdomains_deduplication_and_sorting(self):
        """Verify identical entries from multiple certs are deduplicated and sorted."""
        raw_entries = [
            {"name_value": "z.example.com\na.example.com"},
            {"name_value": "a.example.com\nm.example.com"},
        ]
        assert parse_subdomains(raw_entries, "example.com") == [
            "a.example.com",
            "m.example.com",
            "z.example.com",
        ]

    def test_parse_subdomains_empty_entries(self):
        """Verify empty records or missing fields are safely ignored."""
        raw_entries = [
            {},
            {"name_value": ""},
            {"name_value": None},
            {"name_value": "\n  \n"},
        ]
        assert parse_subdomains(raw_entries, "example.com") == []


class TestCrtshFetching:
    """Test suite for fetch_crtsh_data and streaming network resilience logic."""

    def test_successful_fetch(self, crtsh_sample_data):
        """Verify successful streaming query with correct parameters and identity encoding."""
        captured_requests: list[httpx.Request] = []
        tracked_responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            resp = httpx.Response(200, content=json.dumps(crtsh_sample_data).encode("utf-8"))
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        data = fetch_crtsh_data("example.com", client=client)

        assert data == crtsh_sample_data
        assert len(captured_requests) == 1
        req = captured_requests[0]
        assert str(req.url).startswith(CRTSH_BASE_URL)
        assert req.url.params["q"] == "%.example.com"
        assert req.url.params["output"] == "json"
        assert req.headers["User-Agent"] == USER_AGENT
        assert req.headers["Accept"] == "application/json"
        assert req.headers["Accept-Encoding"] == "identity"
        assert tracked_responses[0].is_closed is True

    def test_retry_on_server_502_then_success(self, mock_sleep):
        """Verify 502 Bad Gateway triggers retry, closes response, and succeeds on attempt 2."""
        call_count = 0
        tracked_responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                resp = httpx.Response(502, content=b"Bad Gateway")
            else:
                resp = httpx.Response(200, content=b'[{"name_value": "sub.example.com"}]')
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        data = fetch_crtsh_data("example.com", client=client)

        assert len(data) == 1
        assert call_count == 2
        mock_sleep.assert_called_once_with(1)
        assert all(r.is_closed for r in tracked_responses)

    def test_retry_on_timeout_and_rate_limit(self, mock_sleep):
        """Verify retries on Timeout and HTTP 429 then succeeds on attempt 3."""
        call_count = 0
        tracked_responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise httpx.TimeoutException("Connection timed out")
            elif call_count == 2:
                resp = httpx.Response(429, content=b"Too Many Requests")
            else:
                resp = httpx.Response(200, content=b'[{"name_value": "app.example.com"}]')
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        data = fetch_crtsh_data("example.com", client=client)

        assert len(data) == 1
        assert call_count == 3
        assert mock_sleep.call_count == 2
        mock_sleep.assert_any_call(1)
        mock_sleep.assert_any_call(2)
        assert all(r.is_closed for r in tracked_responses)

    def test_retry_on_invalid_json_html_error(self, mock_sleep):
        """Verify retrying when response body is HTML rather than valid JSON."""
        call_count = 0
        tracked_responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                resp = httpx.Response(200, content=b"<html>Bad Gateway</html>")
            else:
                resp = httpx.Response(200, content=b"[]")
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        data = fetch_crtsh_data("example.com", client=client)

        assert data == []
        assert call_count == 2
        mock_sleep.assert_called_once_with(1)
        assert all(r.is_closed for r in tracked_responses)

    def test_exhausted_retries_raises_crtsh_error(self, mock_sleep):
        """Verify exhausting all 3 attempts raises CrtshError and closes all responses."""
        call_count = 0
        tracked_responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            resp = httpx.Response(500, content=b"Internal Server Error")
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CrtshError, match="Failed to retrieve data from crt.sh"):
            fetch_crtsh_data("example.com", client=client)

        assert call_count == 3
        assert mock_sleep.call_count == 2
        assert all(r.is_closed for r in tracked_responses)

    def test_non_retryable_404_fails_immediately(self, mock_sleep):
        """Verify non-retryable 4xx errors abort immediately and close response."""
        call_count = 0
        tracked_responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            resp = httpx.Response(404, content=b"Not Found")
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CrtshError, match="client error HTTP 404"):
            fetch_crtsh_data("example.com", client=client)

        assert call_count == 1
        mock_sleep.assert_not_called()
        assert all(r.is_closed for r in tracked_responses)


class TestExceptionHierarchy:
    """Test suite for Discovery error classes."""

    def test_discovery_exception_hierarchy(self):
        """Verify error inheritance."""
        assert issubclass(CrtshError, DiscoveryError)
        assert issubclass(CertSpotterError, DiscoveryError)
        assert issubclass(AllSourcesFailedError, DiscoveryError)
        assert issubclass(DiscoveryConfigurationError, DiscoveryError)

    def test_all_sources_failed_error_preserves_component_messages(self):
        """Verify AllSourcesFailedError retains individual failure messages."""
        err = AllSourcesFailedError(
            message="Both failed",
            crtsh_error="crt.sh timeout",
            certspotter_error="certspotter rate limit",
        )
        assert err.crtsh_error == "crt.sh timeout"
        assert err.certspotter_error == "certspotter rate limit"
        assert "Both failed" in str(err)


class TestCertSpotterFetching:
    """Test suite for fetch_certspotter_data API client, pagination, and retry logic."""

    def test_certspotter_happy_path_with_pagination(self):
        """Verify multi-page pagination terminates on empty array and passes after token."""
        captured_requests: list[httpx.Request] = []
        tracked_responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            page_idx = len(captured_requests)
            if page_idx == 1:
                content = json.dumps([
                    {"id": "iss-101", "dns_names": ["a.example.com"]},
                    {"id": "iss-102", "dns_names": ["b.example.com"]},
                ]).encode("utf-8")
            elif page_idx == 2:
                content = json.dumps([
                    {"id": "iss-103", "dns_names": ["c.example.com"]},
                ]).encode("utf-8")
            else:
                content = b"[]"
            resp = httpx.Response(200, content=content)
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        entries, truncated = fetch_certspotter_data("example.com", client=client)

        assert len(entries) == 3
        assert truncated is False
        assert len(captured_requests) == 3
        assert "after" not in captured_requests[0].url.params
        assert captured_requests[1].url.params["after"] == "iss-102"
        assert captured_requests[2].url.params["after"] == "iss-103"
        assert all(r.is_closed for r in tracked_responses)

    def test_certspotter_rate_limit_retry_after_under_10s(self, mock_sleep):
        """Verify 429 with Retry-After <= 10s waits and retries successfully once."""
        call_count = 0
        tracked_responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                resp = httpx.Response(429, headers={"Retry-After": "4"}, content=b"Rate limited")
            elif call_count == 2:
                resp = httpx.Response(
                    200,
                    content=json.dumps(
                        [{"id": "iss-1", "dns_names": ["app.example.com"]}]
                    ).encode("utf-8"),
                )
            else:
                resp = httpx.Response(200, content=b"[]")
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        entries, truncated = fetch_certspotter_data("example.com", client=client)

        assert len(entries) == 1
        assert truncated is False
        mock_sleep.assert_any_call(4.0)
        assert all(r.is_closed for r in tracked_responses)

    def test_certspotter_rate_limit_retry_after_over_10s_fails(self, mock_sleep):
        """Verify 429 with Retry-After > 10s aborts immediately with CertSpotterError."""
        tracked_responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            resp = httpx.Response(429, headers={"Retry-After": "30"}, content=b"Rate limited")
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CertSpotterError, match="Retry-After=30"):
            fetch_certspotter_data("example.com", client=client)

        assert len(tracked_responses) == 1
        mock_sleep.assert_not_called()
        assert tracked_responses[0].is_closed is True

    def test_certspotter_rate_limit_retry_fails_on_second_429(self, mock_sleep):
        """Verify 429 on second attempt after retry raises CertSpotterError."""
        tracked_responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            resp = httpx.Response(429, headers={"Retry-After": "2"}, content=b"Rate limited")
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CertSpotterError, match="rate limited .* after retry"):
            fetch_certspotter_data("example.com", client=client)

        assert len(tracked_responses) == 2
        mock_sleep.assert_called_once_with(2.0)
        assert all(r.is_closed for r in tracked_responses)

    def test_certspotter_page_cap_truncation(self):
        """Verify pagination stops and sets truncated=True when max_pages limit is reached."""
        tracked_responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            page_idx = len(tracked_responses) + 1
            resp = httpx.Response(
                200,
                content=json.dumps([
                    {"id": str(page_idx), "dns_names": [f"p{page_idx}.example.com"]}
                ]).encode("utf-8"),
            )
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        entries, truncated = fetch_certspotter_data(
            "example.com", client=client, max_pages=2
        )

        assert len(entries) == 2
        assert truncated is True
        assert len(tracked_responses) == 2
        assert all(r.is_closed for r in tracked_responses)

    def test_certspotter_entry_cap_truncation(self):
        """Verify fetching stops and sets truncated=True when max_entries limit is reached."""
        tracked_responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            resp = httpx.Response(
                200,
                content=json.dumps([
                    {"id": "1", "dns_names": ["a.example.com"]},
                    {"id": "2", "dns_names": ["b.example.com"]},
                    {"id": "3", "dns_names": ["c.example.com"]},
                ]).encode("utf-8"),
            )
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        entries, truncated = fetch_certspotter_data(
            "example.com", client=client, max_entries=2
        )

        assert len(entries) == 2
        assert truncated is True
        assert len(tracked_responses) == 1
        assert tracked_responses[0].is_closed is True

    def test_certspotter_api_key_sent_as_bearer_and_not_leaked(self):
        """Verify API key is passed in Authorization header and not disclosed on error."""
        captured_requests: list[httpx.Request] = []
        tracked_responses: list[httpx.Response] = []
        secret_key = "secret_certspotter_api_key_value"

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            resp = httpx.Response(403, content=b"Forbidden: Invalid token")
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CertSpotterError) as exc_info:
            fetch_certspotter_data("example.com", client=client, api_key=secret_key)

        assert captured_requests[0].headers["Authorization"] == f"Bearer {secret_key}"
        assert secret_key not in str(exc_info.value)
        assert tracked_responses[0].is_closed is True


class TestCertSpotterTransformation:
    """Test suite for transform_certspotter_to_raw_records and parsing integration."""

    def test_transform_certspotter_to_raw_records(self):
        """Verify Cert Spotter dns_names array adapts cleanly to name_value records."""
        cs_entries = [
            {"id": "1", "dns_names": ["api.example.com", "*.corp.example.com"]},
            {"id": "2", "dns_names": "invalid-not-a-list"},
            {"id": "3", "dns_names": []},
            {"id": "4"},
            {"id": "5", "dns_names": ["clean.example.com"]},
        ]

        adapted = transform_certspotter_to_raw_records(cs_entries)
        assert len(adapted) == 2
        assert adapted[0] == {"name_value": "api.example.com\n*.corp.example.com"}
        assert adapted[1] == {"name_value": "clean.example.com"}

        subdomains = parse_subdomains(adapted, "example.com")
        assert subdomains == ["api.example.com", "clean.example.com", "corp.example.com"]


class TestDiscoverSubdomainsOrchestrator:
    """Test suite for discover_subdomains primary and fallback orchestrator."""

    def test_discover_subdomains_crtsh_success_does_not_call_certspotter(self):
        """Verify primary crt.sh success does not invoke Cert Spotter."""
        mock_crtsh = MagicMock(return_value=[{"name_value": "api.example.com"}])

        with patch("asm.discovery.fetch_certspotter_data") as mock_cs:
            names, source, fallback_reason, truncated = discover_subdomains(
                "example.com", crtsh_fetcher=mock_crtsh
            )

            assert names == ["api.example.com"]
            assert source == "crt.sh"
            assert fallback_reason is None
            assert truncated is False
            mock_cs.assert_not_called()

    def test_discover_subdomains_fallback_on_crtsh_failure(self):
        """Verify crt.sh CrtshError triggers fallback to Cert Spotter."""
        mock_crtsh = MagicMock(side_effect=CrtshError("crt.sh timed out"))

        cs_mock_data = ([{"dns_names": ["fallback.example.com"]}], False)
        with patch("asm.discovery.fetch_certspotter_data", return_value=cs_mock_data) as mock_cs:
            names, source, fallback_reason, truncated = discover_subdomains(
                "example.com", crtsh_fetcher=mock_crtsh
            )

            assert names == ["fallback.example.com"]
            assert source == "certspotter"
            assert fallback_reason == "crt.sh timed out"
            assert truncated is False
            mock_cs.assert_called_once()

    def test_discover_subdomains_all_sources_failed(self):
        """Verify AllSourcesFailedError is raised when both crt.sh and Cert Spotter fail."""
        mock_crtsh = MagicMock(side_effect=CrtshError("crt.sh 502 Bad Gateway"))

        with patch(
            "asm.discovery.fetch_certspotter_data",
            side_effect=CertSpotterError("Cert Spotter 429 rate limit"),
        ):
            with pytest.raises(AllSourcesFailedError) as exc_info:
                discover_subdomains("example.com", crtsh_fetcher=mock_crtsh)

            err = exc_info.value
            assert err.crtsh_error == "crt.sh 502 Bad Gateway"
            assert err.certspotter_error == "Cert Spotter 429 rate limit"
            assert "crt.sh error: crt.sh 502 Bad Gateway" in str(err)
            assert "Cert Spotter error: Cert Spotter 429 rate limit" in str(err)


class TestCrtshTransportErrors:
    """P1: protocol-level disconnects from crt.sh are retried, then raise CrtshError."""

    def test_remote_protocol_error_raises_crtsh_error(self, mock_sleep):
        """'Server disconnected' must become CrtshError so the Cert Spotter fallback runs."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            raise httpx.RemoteProtocolError("Server disconnected without sending a response.")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CrtshError):
            fetch_crtsh_data("example.com", client=client)

        assert call_count == 3


class TestBoundedHostnameSelection:
    """Test suite for select_bounded_subdomains deterministic selection and capping."""

    def test_selection_below_limit(self):
        names = ["a.example.com", "b.example.com", "c.example.com"]
        selected, truncated, observed = select_bounded_subdomains(
            names, "example.com", max_hosts=5
        )
        assert selected == ["a.example.com", "b.example.com", "c.example.com"]
        assert truncated is False
        assert observed == 3

    def test_selection_exactly_at_limit(self):
        names = [f"sub{i}.example.com" for i in range(5)]
        selected, truncated, observed = select_bounded_subdomains(
            names, "example.com", max_hosts=5
        )
        assert len(selected) == 5
        assert truncated is False
        assert observed == 5

    def test_selection_above_limit(self):
        names = [f"sub{i:02d}.example.com" for i in range(10)]
        selected, truncated, observed = select_bounded_subdomains(
            names, "example.com", max_hosts=4
        )
        assert len(selected) == 4
        assert selected == [
            "sub00.example.com",
            "sub01.example.com",
            "sub02.example.com",
            "sub03.example.com",
        ]
        assert truncated is True
        assert observed == 10

    def test_selection_apex_prioritization_when_present(self):
        names = ["z.example.com", "example.com", "a.example.com", "m.example.com"]
        selected, truncated, observed = select_bounded_subdomains(
            names, "example.com", max_hosts=3
        )
        assert selected == ["example.com", "a.example.com", "m.example.com"]
        assert truncated is True
        assert observed == 4

    def test_selection_apex_not_added_when_absent(self):
        names = ["z.example.com", "a.example.com", "m.example.com"]
        selected, truncated, observed = select_bounded_subdomains(
            names, "example.com", max_hosts=2
        )
        assert "example.com" not in selected
        assert selected == ["a.example.com", "m.example.com"]
        assert truncated is True
        assert observed == 3

    def test_selection_deterministic_regardless_of_input_order(self):
        order1 = [
            "c.example.com",
            "example.com",
            "a.example.com",
            "b.example.com",
            "d.example.com",
        ]
        order2 = [
            "b.example.com",
            "d.example.com",
            "example.com",
            "c.example.com",
            "a.example.com",
        ]
        sel1, trunc1, obs1 = select_bounded_subdomains(order1, "example.com", max_hosts=3)
        sel2, trunc2, obs2 = select_bounded_subdomains(order2, "example.com", max_hosts=3)
        assert sel1 == sel2 == ["example.com", "a.example.com", "b.example.com"]
        assert trunc1 == trunc2 is True
        assert obs1 == obs2 == 5

    def test_selection_zero_or_negative_hosts_raises_configuration_error(self):
        names = ["a.example.com", "b.example.com"]
        with pytest.raises(DiscoveryConfigurationError, match="must be a positive integer > 0"):
            select_bounded_subdomains(names, "example.com", max_hosts=0)
        with pytest.raises(DiscoveryConfigurationError, match="must be a positive integer > 0"):
            select_bounded_subdomains(names, "example.com", max_hosts=-5)


class TestResponseByteLimitsAndEncoding:
    """Test suite for streaming response byte bounds, encoding rejection, and cumulative limits."""

    @pytest.mark.parametrize("status_code", [200, 400, 404, 429, 500, 502])
    def test_crtsh_rejects_non_identity_content_encoding_on_all_statuses(self, status_code):
        """Verify non-identity encoding is rejected before body consumption on every HTTP status."""
        body_consumed = False

        def body_generator():
            nonlocal body_consumed
            body_consumed = True
            yield b"\x1f\x8b\x08fake-gzip-data"

        tracked_response = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal tracked_response
            tracked_response = httpx.Response(
                status_code,
                content=body_generator(),
                headers={"Content-Encoding": "gzip"},
            )
            return tracked_response

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CrtshError) as exc_info:
            fetch_crtsh_data("example.com", client=client)

        assert "non-identity encoding rejected" in str(exc_info.value)
        assert body_consumed is False, "Body was consumed despite non-identity Content-Encoding"
        assert tracked_response is not None and tracked_response.is_closed is True

    @pytest.mark.parametrize("status_code", [200, 400, 404, 429, 500, 502])
    def test_certspotter_rejects_non_identity_content_encoding_on_all_statuses(self, status_code):
        """Verify Cert Spotter rejects non-identity encoding without consuming body."""
        body_consumed = False

        def body_generator():
            nonlocal body_consumed
            body_consumed = True
            yield b"brotli-compressed-data"

        tracked_response = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal tracked_response
            tracked_response = httpx.Response(
                status_code,
                content=body_generator(),
                headers={"Content-Encoding": "br"},
            )
            return tracked_response

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CertSpotterError) as exc_info:
            fetch_certspotter_data("example.com", client=client)

        assert "non-identity encoding rejected" in str(exc_info.value)
        assert body_consumed is False, "Body was consumed despite non-identity Content-Encoding"
        assert tracked_response is not None and tracked_response.is_closed is True

    def test_oversized_uncompressed_error_body_does_not_buffer_fully(self):
        """Verify error handling reads bounded preview without full buffering."""
        chunks_yielded = 0

        def large_error_stream():
            nonlocal chunks_yielded
            for _ in range(500):  # 500 * 4096 = 2 MiB
                chunks_yielded += 1
                yield b"E" * 4096

        tracked_response = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal tracked_response
            tracked_response = httpx.Response(500, content=large_error_stream())
            return tracked_response

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CrtshError, match="Server error HTTP 500"):
            fetch_crtsh_data("example.com", client=client)

        # 3 retry attempts, each should read at most 2-3 chunks (8192 byte limit)
        assert chunks_yielded < 30, f"Excessive chunks read: {chunks_yielded}"
        assert tracked_response is not None and tracked_response.is_closed is True

    def test_error_preview_large_single_chunk_retains_only_configured_allowance(self):
        """Verify helper retains only max_bytes even if transport yields one 64 KiB chunk."""
        # Single chunk of 64 KiB
        chunk_data = b"CUSTOM_ERROR_PREFIX_" + b"K" * (65536 - 20)

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, content=iter([chunk_data]))

        budget = CumulativeBudget(max_total_bytes=100000)
        client = httpx.Client(transport=httpx.MockTransport(handler))
        resp = client.get("https://example.com/api")

        preview, total_bytes = _read_error_text_bounded(
            resp,
            provider_name="crt.sh",
            max_bytes=4096,
            budget=budget,
        )

        assert total_bytes == 65536
        assert budget.consumed_bytes == 65536
        assert resp.is_closed is True
        assert preview.startswith("CUSTOM_ERROR_PREFIX_")
        assert len(preview) <= 200

    def test_crtsh_error_large_single_chunk_bounds_preview_and_closes_response(self):
        """Verify crt.sh error handling with single large chunk bounds preview and closes."""
        chunk_data = b"CRTSH_SINGLE_LARGE_ERROR_" + b"Z" * (65536 - 25)
        tracked_response = None

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal tracked_response
            tracked_response = httpx.Response(400, content=iter([chunk_data]))
            return tracked_response

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CrtshError) as exc_info:
            fetch_crtsh_data("example.com", client=client)

        err_text = str(exc_info.value)
        assert "CRTSH_SINGLE_LARGE_ERROR_" in err_text
        # Preview is bounded to 200 chars, total exception message is well below 1000 chars
        assert len(err_text) < 1000
        assert tracked_response is not None and tracked_response.is_closed is True

    def test_crtsh_content_length_exceeds_budget(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=b"[]",
                headers={"Content-Length": "20971520"},  # 20 MiB
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CrtshError) as exc_info:
            fetch_crtsh_data("example.com", client=client, max_bytes=1048576)
        assert "exceeds limit" in str(exc_info.value)

    def test_certspotter_content_length_exceeds_budget(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=b"[]",
                headers={"Content-Length": "5242880"},
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CertSpotterError) as exc_info:
            fetch_certspotter_data("example.com", client=client, max_page_bytes=2097152)
        assert "exceeds limit" in str(exc_info.value)

    def test_streamed_bytes_exceed_budget_without_content_length(self):
        def stream_gen():
            for _ in range(10):
                yield b"X" * 1024

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=stream_gen())

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CrtshError) as exc_info:
            fetch_crtsh_data("example.com", client=client, max_bytes=4096)
        assert "response exceeded limit of 4096 bytes" in str(exc_info.value)

    def test_certspotter_cumulative_accounting_includes_errors_and_retries(self):
        """Verify cumulative transfer budget accounts for error bodies and retries across pages."""
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Page 1: returns 1200 bytes
                entries = [{"id": "1", "dns_names": ["p1.example.com"]}]
                body = (json.dumps(entries) + " " * 1100).encode("utf-8")
                return httpx.Response(200, content=body)
            elif call_count == 2:
                # Page 2 Attempt 1: 502 with 500 bytes of error body
                return httpx.Response(502, content=b"E" * 500)
            else:
                # Page 2 Attempt 2: tries to return 500 bytes (cumulative: 2200 > 2000)
                entries = [{"id": "2", "dns_names": ["p2.example.com"]}]
                body = (json.dumps(entries) + " " * 400).encode("utf-8")
                return httpx.Response(200, content=body)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with pytest.raises(CertSpotterError) as exc_info:
            fetch_certspotter_data(
                "example.com",
                client=client,
                max_total_bytes=2000,
                max_page_bytes=1800,
            )
        err_msg = str(exc_info.value).lower()
        assert "exceed" in err_msg and ("limit" in err_msg or "budget" in err_msg)

    def test_resource_limit_failure_triggers_fallback_then_explicit_failure(self):
        def crtsh_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"[]", headers={"Content-Length": "999999999"})

        client = httpx.Client(transport=httpx.MockTransport(crtsh_handler))
        with patch(
            "asm.discovery.fetch_certspotter_data",
            side_effect=CertSpotterError("Cert Spotter cumulative byte cap exceeded"),
        ):
            with pytest.raises(AllSourcesFailedError) as exc_info:
                discover_subdomains("example.com", client=client, max_response_bytes=1000)

            err = exc_info.value
            assert "Content-Length" in err.crtsh_error
            assert "cumulative byte cap exceeded" in err.certspotter_error


class TestConfigurationValidation:
    """Test suite for explicit configuration validation and error handling."""

    def test_invalid_discovery_max_response_bytes_raises(self, monkeypatch):
        monkeypatch.setenv("DISCOVERY_MAX_RESPONSE_BYTES", "0")
        with pytest.raises(DiscoveryConfigurationError, match="must be a positive integer > 0"):
            get_discovery_max_response_bytes()

        monkeypatch.setenv("DISCOVERY_MAX_RESPONSE_BYTES", "-10")
        with pytest.raises(DiscoveryConfigurationError, match="must be a positive integer > 0"):
            get_discovery_max_response_bytes()

        monkeypatch.setenv("DISCOVERY_MAX_RESPONSE_BYTES", "invalid_number")
        with pytest.raises(DiscoveryConfigurationError, match="must be a valid integer"):
            get_discovery_max_response_bytes()

    def test_invalid_discovery_max_hosts_raises(self, monkeypatch):
        monkeypatch.setenv("DISCOVERY_MAX_HOSTS", "0")
        with pytest.raises(DiscoveryConfigurationError, match="must be a positive integer > 0"):
            get_discovery_max_hosts()

        monkeypatch.setenv("DISCOVERY_MAX_HOSTS", "-50")
        with pytest.raises(DiscoveryConfigurationError, match="must be a positive integer > 0"):
            get_discovery_max_hosts()

        monkeypatch.setenv("DISCOVERY_MAX_HOSTS", "bad_int")
        with pytest.raises(DiscoveryConfigurationError, match="must be a valid integer"):
            get_discovery_max_hosts()

    def test_invalid_direct_arguments_raise(self):
        with pytest.raises(DiscoveryConfigurationError, match="must be a positive integer > 0"):
            discover_subdomains("example.com", max_hosts=0)

        with pytest.raises(DiscoveryConfigurationError, match="must be a positive integer > 0"):
            discover_subdomains("example.com", max_response_bytes=-100)


class TestTruncationMetadataAndDownstream:
    """Test suite for truncation reason attribution, UI exposure, and downstream exclusion."""

    def test_discover_subdomains_hostname_cap_truncation(self):
        entries = [{"name_value": f"sub{i}.example.com"} for i in range(10)]
        mock_fetcher = MagicMock(return_value=entries)

        outcome = discover_subdomains(
            "example.com",
            crtsh_fetcher=mock_fetcher,
            max_hosts=3,
        )
        assert isinstance(outcome, DiscoveryOutcome)
        assert len(outcome.subdomains) == 3
        assert outcome.truncated is True
        assert outcome.truncation_reason == "hostname_cap_exceeded"
        assert outcome.observed_count == 10

    def test_discover_subdomains_provider_truncation_retained_when_under_host_cap(self):
        mock_crtsh = MagicMock(side_effect=CrtshError("crt.sh unavailable"))
        cs_entries = [
            {"id": "1", "dns_names": ["a.example.com"]},
            {"id": "2", "dns_names": ["b.example.com"]},
        ]
        with patch("asm.discovery.fetch_certspotter_data", return_value=(cs_entries, True)):
            outcome = discover_subdomains(
                "example.com",
                crtsh_fetcher=mock_crtsh,
                max_hosts=10,
            )
            assert outcome.truncated is True
            assert outcome.truncation_reason == "provider_entry_limit"
            assert outcome.observed_count == 2
            assert len(outcome.subdomains) == 2

    def test_discover_subdomains_provider_and_hostname_cap_combined(self):
        mock_crtsh = MagicMock(side_effect=CrtshError("crt.sh unavailable"))
        cs_entries = [
            {"id": str(i), "dns_names": [f"sub{i}.example.com"]} for i in range(8)
        ]
        with patch("asm.discovery.fetch_certspotter_data", return_value=(cs_entries, True)):
            outcome = discover_subdomains(
                "example.com",
                crtsh_fetcher=mock_crtsh,
                max_hosts=4,
            )
            assert outcome.truncated is True
            assert outcome.truncation_reason == "provider_and_hostname_cap_exceeded"
            assert outcome.observed_count == 8
            assert len(outcome.subdomains) == 4

    def test_downstream_stages_never_receive_excluded_hosts(self):
        from asm.worker.runner import DirectScannerRunner

        runner = DirectScannerRunner()
        discover_report = {
            "domain": "example.com",
            "truncated": True,
            "truncation_reason": "hostname_cap_exceeded",
            "counts": {
                "total_discovered": 2,
                "selected_hosts": 2,
                "observed_hosts": 5,
                "unresolved": 0,
            },
            "results": [
                {"subdomain": "selected1.example.com", "resolved": True},
                {"subdomain": "selected2.example.com", "resolved": True},
            ],
        }

        with patch("asm.worker.runner.probe_hosts_concurrently", return_value=[]) as mock_probe:
            runner.run_probe("example.com", discover_report, authorized=True)
            mock_probe.assert_called_once_with(
                ["selected1.example.com", "selected2.example.com"],
                "example.com",
                max_workers=10,
            )

    def test_ui_notice_in_pipeline_stages(self):
        from datetime import UTC, datetime

        from asm.api.routes_ui import get_org_scan_detail_ui
        from asm.db.models import Domain, Membership, Organization, ScanResult, ScanRun, ScanStage

        mock_db = MagicMock()
        mock_org = Organization(id=1, name="Test Org")
        mock_membership = Membership(id=1, org_id=1, user_id="u1", role="owner")
        mock_domain = Domain(id=10, org_id=1, name="example.com")
        mock_scan = ScanRun(
            id=100, domain_id=10, domain=mock_domain, status="completed", trigger="manual"
        )
        mock_scan.created_at = datetime.now(UTC)

        disc_result = ScanResult(
            id=1,
            scan_run_id=100,
            stage="discover",
            report={
                "truncated": True,
                "truncation_reason": "hostname_cap_exceeded",
                "counts": {"selected_hosts": 1000, "observed_hosts": 3450},
                "source": "crt.sh",
            },
        )
        stage_discover = ScanStage(
            id=1, scan_run_id=100, stage="discover", status="completed", duration_ms=250
        )

        with patch("asm.api.routes_ui.get_scan_for_org", return_value=mock_scan):
            mock_db.scalars.side_effect = [
                MagicMock(all=lambda: [disc_result]),  # ScanResult
                MagicMock(all=lambda: []),  # ScanChange
                MagicMock(all=lambda: [stage_discover]),  # ScanStage
            ]
            response = MagicMock()
            response.headers = {}
            auth_settings = MagicMock()
            auth_settings.supabase_url = "https://test.supabase.co"

            html = get_org_scan_detail_ui(
                org_id=1,
                scan_id=100,
                response=response,
                auth_context=(mock_org, mock_membership),
                auth_settings=auth_settings,
                db=mock_db,
            )
            assert "Discovery capped at 1000 hostnames (3450 observed)" in html
            assert "Remaining hostnames were excluded from scanning." in html

    def test_ui_notice_historical_report_without_truncation_reason(self):
        from datetime import UTC, datetime

        from asm.api.routes_ui import get_org_scan_detail_ui
        from asm.db.models import Domain, Membership, Organization, ScanResult, ScanRun, ScanStage

        mock_db = MagicMock()
        mock_org = Organization(id=1, name="Test Org")
        mock_membership = Membership(id=1, org_id=1, user_id="u1", role="owner")
        mock_domain = Domain(id=10, org_id=1, name="example.com")
        mock_scan = ScanRun(
            id=101, domain_id=10, domain=mock_domain, status="completed", trigger="manual"
        )
        mock_scan.created_at = datetime.now(UTC)

        # Historical report: truncated=True, but no truncation_reason field
        disc_result = ScanResult(
            id=2,
            scan_run_id=101,
            stage="discover",
            report={
                "truncated": True,
                "counts": {"total_discovered": 500},
                "source": "crt.sh",
            },
        )
        stage_discover = ScanStage(
            id=2, scan_run_id=101, stage="discover", status="completed", duration_ms=180
        )

        with patch("asm.api.routes_ui.get_scan_for_org", return_value=mock_scan):
            mock_db.scalars.side_effect = [
                MagicMock(all=lambda: [disc_result]),
                MagicMock(all=lambda: []),
                MagicMock(all=lambda: [stage_discover]),
            ]
            response = MagicMock()
            response.headers = {}
            auth_settings = MagicMock()
            auth_settings.supabase_url = "https://test.supabase.co"

            html = get_org_scan_detail_ui(
                org_id=1,
                scan_id=101,
                response=response,
                auth_context=(mock_org, mock_membership),
                auth_settings=auth_settings,
                db=mock_db,
            )
            assert "Discovery results were truncated due to resource or provider limits." in html


class TestDirectArgumentValidation:
    """Test that _validate_positive_int and entrypoints reject invalid types."""

    @pytest.mark.parametrize(
        "invalid_val",
        ["1000", "0", "-1", "abc", 1.5, 0.0, -2.5, True, False, [], {}],
    )
    def test_validate_positive_int_rejects_non_ints_and_non_positives(self, invalid_val):
        with pytest.raises(DiscoveryConfigurationError, match="must be a positive integer > 0"):
            _validate_positive_int(invalid_val, "test_param")

    def test_validate_positive_int_accepts_positive_ints(self):
        _validate_positive_int(1, "test_param")
        _validate_positive_int(1000, "test_param")

    def test_validate_positive_int_preserves_none(self):
        _validate_positive_int(None, "test_param")  # does not raise

    def test_fetch_crtsh_data_rejects_invalid_max_bytes(self):
        err = "max_bytes must be a positive integer > 0"
        with pytest.raises(DiscoveryConfigurationError, match=err):
            fetch_crtsh_data("example.com", max_bytes="not-an-int")  # type: ignore

        with pytest.raises(DiscoveryConfigurationError, match=err):
            fetch_crtsh_data("example.com", max_bytes=True)  # type: ignore

        with pytest.raises(DiscoveryConfigurationError, match=err):
            fetch_crtsh_data("example.com", max_bytes=1.5)  # type: ignore

    def test_fetch_certspotter_data_rejects_invalid_params(self):
        err_pages = "max_pages must be a positive integer"
        with pytest.raises(DiscoveryConfigurationError, match=err_pages):
            fetch_certspotter_data("example.com", max_pages=False)  # type: ignore

        with pytest.raises(DiscoveryConfigurationError, match="max_total_bytes must be a positive"):
            fetch_certspotter_data("example.com", max_total_bytes="1000")  # type: ignore

    def test_select_bounded_subdomains_rejects_invalid_max_hosts(self):
        err = "max_hosts must be a positive integer > 0"
        with pytest.raises(DiscoveryConfigurationError, match=err):
            select_bounded_subdomains(["a.com"], "a.com", max_hosts=1.5)  # type: ignore

        with pytest.raises(DiscoveryConfigurationError, match=err):
            select_bounded_subdomains(["a.com"], "a.com", max_hosts=True)  # type: ignore

    def test_discover_subdomains_rejects_invalid_limits(self):
        err_hosts = "max_hosts must be a positive integer"
        with pytest.raises(DiscoveryConfigurationError, match=err_hosts):
            discover_subdomains("example.com", max_hosts="100")  # type: ignore

        err = "max_response_bytes must be a positive integer > 0"
        with pytest.raises(DiscoveryConfigurationError, match=err):
            discover_subdomains("example.com", max_response_bytes=False)  # type: ignore


class TestCertSpotterStreamingBudgetAccounting:
    """Regressions for charging bytes as they are consumed and surviving partial response errors."""

    def test_response_yields_bytes_then_raises_read_timeout(self, mock_sleep):
        """A response yields bytes then raises ReadTimeout: bytes are charged and closed."""
        budget = CumulativeBudget(max_total_bytes=5000)
        tracked_responses: list[httpx.Response] = []

        def make_stream():
            yield b"X" * 500
            raise httpx.ReadTimeout("read timed out during stream")

        def handler(request: httpx.Request) -> httpx.Response:
            resp = httpx.Response(200, content=make_stream())
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        err = "Failed to retrieve data from Cert Spotter after 3 attempts"
        with pytest.raises(CertSpotterError, match=err):
            _fetch_certspotter_page(
                active_client=client,
                params={"domain": "example.com"},
                headers={},
                domain="example.com",
                max_page_bytes=2000,
                budget=budget,
            )

        # 3 attempts made, each consumed 500 bytes before ReadTimeout -> 1500 bytes charged
        assert budget.consumed_bytes == 1500
        assert len(tracked_responses) == 3
        assert all(r.is_closed for r in tracked_responses)

    def test_response_yields_bytes_then_raises_transport_error(self, mock_sleep):
        """A response yields bytes then raises transport error: bytes charged and closed."""
        budget = CumulativeBudget(max_total_bytes=5000)
        tracked_responses: list[httpx.Response] = []

        def make_stream():
            yield b"Y" * 400
            raise httpx.NetworkError("connection reset by peer")

        def handler(request: httpx.Request) -> httpx.Response:
            resp = httpx.Response(200, content=make_stream())
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        err = "Failed to retrieve data from Cert Spotter after 3 attempts"
        with pytest.raises(CertSpotterError, match=err):
            _fetch_certspotter_page(
                active_client=client,
                params={"domain": "example.com"},
                headers={},
                domain="example.com",
                max_page_bytes=2000,
                budget=budget,
            )

        assert budget.consumed_bytes == 1200  # 400 * 3 attempts
        assert len(tracked_responses) == 3
        assert all(r.is_closed for r in tracked_responses)

    def test_subsequent_retry_exceeds_remaining_budget(self, mock_sleep):
        """Attempt 1 consumes 800 bytes; retry consumes 300 bytes and exceeds 1000 budget."""
        budget = CumulativeBudget(max_total_bytes=1000)
        call_count = 0
        tracked_responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                def stream1():
                    yield b"A" * 800
                    raise httpx.ReadTimeout("attempt 1 timeout")

                resp = httpx.Response(200, content=stream1())
            else:
                def stream2():
                    yield b"B" * 300
                    yield b"C" * 100

                resp = httpx.Response(200, content=stream2())
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        err = "cumulative transfer exceeded budget of 1000 bytes"
        with pytest.raises(CertSpotterError, match=err):
            _fetch_certspotter_page(
                active_client=client,
                params={"domain": "example.com"},
                headers={},
                domain="example.com",
                max_page_bytes=2000,
                budget=budget,
            )

        # Retries must NOT reset the budget: 800 + 300 = 1100 charged, aborted on 300 chunk
        assert budget.consumed_bytes == 1100
        assert call_count == 2
        assert len(tracked_responses) == 2
        assert all(r.is_closed for r in tracked_responses)

    def test_error_response_fails_partway_through_reading(self, mock_sleep):
        """Error response (502) yields error bytes then fails: bytes charged and closed."""
        budget = CumulativeBudget(max_total_bytes=2000)
        tracked_responses: list[httpx.Response] = []

        def handler(request: httpx.Request) -> httpx.Response:
            def err_stream():
                yield b"Bad Gateway Part 1 " * 20  # 380 bytes
                raise httpx.ReadTimeout("stream dropped during error body")

            resp = httpx.Response(502, content=err_stream())
            tracked_responses.append(resp)
            return resp

        client = httpx.Client(transport=httpx.MockTransport(handler))
        err = "Failed to retrieve data from Cert Spotter after 3 attempts"
        with pytest.raises(CertSpotterError, match=err):
            _fetch_certspotter_page(
                active_client=client,
                params={"domain": "example.com"},
                headers={},
                domain="example.com",
                max_page_bytes=1000,
                budget=budget,
            )

        assert budget.consumed_bytes == 380 * 3
        assert len(tracked_responses) == 3
        assert all(r.is_closed for r in tracked_responses)
