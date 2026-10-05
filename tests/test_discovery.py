"""Unit tests for crt.sh discovery and parsing module."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from asm.discovery import (
    CRTSH_BASE_URL,
    USER_AGENT,
    AllSourcesFailedError,
    CertSpotterError,
    CrtshError,
    DiscoveryError,
    discover_subdomains,
    fetch_certspotter_data,
    fetch_crtsh_data,
    parse_subdomains,
    transform_certspotter_to_raw_records,
)


class TestSubdomainParsing:
    """Test suite for parse_subdomains using mock and fixture data."""

    def test_parse_subdomains_from_fixture(self, crtsh_sample_data):
        """Verify parsing handles wildcards, newlines, duplicates, emails, and scope."""
        target_domain = "example.com"
        results = parse_subdomains(crtsh_sample_data, target_domain)

        # Expected subdomains:
        # - example.com (from *.example.com and example.com)
        # - api.example.com (from api.example.com)
        # - dev.example.com (from multi-line)
        # - staging.example.com (from multi-line)
        # - corp.example.com (from *.corp.example.com)
        # - vpn.corp.example.com (from vpn.corp.example.com)
        # Excluded:
        # - admin@example.com (email)
        # - support@example.com (email)
        # - unrelated.org, sub.unrelated.org (out of scope)
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
    """Test suite for fetch_crtsh_data and network resilience logic."""

    def test_successful_fetch(self, crtsh_sample_data):
        """Verify successful query with correct parameters and headers."""
        client_mock = MagicMock(spec=httpx.Client)
        response_mock = MagicMock(spec=httpx.Response)
        response_mock.status_code = 200
        response_mock.json.return_value = crtsh_sample_data
        client_mock.get.return_value = response_mock

        data = fetch_crtsh_data("example.com", client=client_mock)

        assert data == crtsh_sample_data
        client_mock.get.assert_called_once_with(
            CRTSH_BASE_URL,
            params={"q": "%.example.com", "output": "json"},
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )

    def test_retry_on_server_502_then_success(self, mock_sleep):
        """Verify 502 Bad Gateway triggers a retry and succeeds on attempt 2."""
        client_mock = MagicMock(spec=httpx.Client)

        resp_502 = MagicMock(spec=httpx.Response)
        resp_502.status_code = 502

        resp_200 = MagicMock(spec=httpx.Response)
        resp_200.status_code = 200
        resp_200.json.return_value = [{"name_value": "sub.example.com"}]

        client_mock.get.side_effect = [resp_502, resp_200]

        data = fetch_crtsh_data("example.com", client=client_mock)
        assert len(data) == 1
        assert client_mock.get.call_count == 2
        mock_sleep.assert_called_once_with(1)

    def test_retry_on_timeout_and_rate_limit(self, mock_sleep):
        """Verify retries on Timeout and HTTP 429 then succeeds on attempt 3."""
        client_mock = MagicMock(spec=httpx.Client)

        timeout_exc = httpx.TimeoutException("Connection timed out")

        resp_429 = MagicMock(spec=httpx.Response)
        resp_429.status_code = 429

        resp_200 = MagicMock(spec=httpx.Response)
        resp_200.status_code = 200
        resp_200.json.return_value = [{"name_value": "app.example.com"}]

        client_mock.get.side_effect = [timeout_exc, resp_429, resp_200]

        data = fetch_crtsh_data("example.com", client=client_mock)
        assert len(data) == 1
        assert client_mock.get.call_count == 3
        # Should have slept with 1s then 2s
        assert mock_sleep.call_count == 2
        mock_sleep.assert_any_call(1)
        mock_sleep.assert_any_call(2)

    def test_retry_on_invalid_json_html_error(self, mock_sleep):
        """Verify retrying when response body is HTML rather than valid JSON."""
        client_mock = MagicMock(spec=httpx.Client)

        resp_bad_json = MagicMock(spec=httpx.Response)
        resp_bad_json.status_code = 200
        resp_bad_json.json.side_effect = ValueError("Invalid JSON")

        resp_200 = MagicMock(spec=httpx.Response)
        resp_200.status_code = 200
        resp_200.json.return_value = []

        client_mock.get.side_effect = [resp_bad_json, resp_200]

        data = fetch_crtsh_data("example.com", client=client_mock)
        assert data == []
        assert client_mock.get.call_count == 2
        mock_sleep.assert_called_once_with(1)

    def test_exhausted_retries_raises_crtsh_error(self, mock_sleep):
        """Verify exhausting all 3 attempts raises CrtshError."""
        client_mock = MagicMock(spec=httpx.Client)
        resp_500 = MagicMock(spec=httpx.Response)
        resp_500.status_code = 500
        client_mock.get.return_value = resp_500

        with pytest.raises(CrtshError, match="Failed to retrieve data from crt.sh"):
            fetch_crtsh_data("example.com", client=client_mock)

        assert client_mock.get.call_count == 3
        assert mock_sleep.call_count == 2

    def test_non_retryable_404_fails_immediately(self, mock_sleep):
        """Verify non-retryable 4xx errors like 404 abort immediately without retrying."""
        client_mock = MagicMock(spec=httpx.Client)
        resp_404 = MagicMock(spec=httpx.Response)
        resp_404.status_code = 404
        resp_404.text = "Not Found"
        client_mock.get.return_value = resp_404

        with pytest.raises(CrtshError, match="client error HTTP 404"):
            fetch_crtsh_data("example.com", client=client_mock)

        assert client_mock.get.call_count == 1
        mock_sleep.assert_not_called()


class TestExceptionHierarchy:
    """Test suite for Discovery error classes."""

    def test_discovery_exception_hierarchy(self):
        """Verify CrtshError, CertSpotterError, and AllSourcesFailedError inherit DiscoveryError."""
        assert issubclass(CrtshError, DiscoveryError)
        assert issubclass(CertSpotterError, DiscoveryError)
        assert issubclass(AllSourcesFailedError, DiscoveryError)

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
        client_mock = MagicMock(spec=httpx.Client)

        resp_page1 = MagicMock(spec=httpx.Response)
        resp_page1.status_code = 200
        resp_page1.json.return_value = [
            {"id": "iss-101", "dns_names": ["a.example.com"]},
            {"id": "iss-102", "dns_names": ["b.example.com"]},
        ]

        resp_page2 = MagicMock(spec=httpx.Response)
        resp_page2.status_code = 200
        resp_page2.json.return_value = [
            {"id": "iss-103", "dns_names": ["c.example.com"]},
        ]

        resp_page3 = MagicMock(spec=httpx.Response)
        resp_page3.status_code = 200
        resp_page3.json.return_value = []

        client_mock.get.side_effect = [resp_page1, resp_page2, resp_page3]

        entries, truncated = fetch_certspotter_data("example.com", client=client_mock)

        assert len(entries) == 3
        assert truncated is False
        assert client_mock.get.call_count == 3

        # Verify query parameters for pagination
        call_args_list = client_mock.get.call_args_list
        assert "after" not in call_args_list[0].kwargs["params"]
        assert call_args_list[1].kwargs["params"]["after"] == "iss-102"
        assert call_args_list[2].kwargs["params"]["after"] == "iss-103"

    def test_certspotter_rate_limit_retry_after_under_10s(self, mock_sleep):
        """Verify 429 with Retry-After <= 10s waits and retries successfully once."""
        client_mock = MagicMock(spec=httpx.Client)

        resp_429 = MagicMock(spec=httpx.Response)
        resp_429.status_code = 429
        resp_429.headers = {"Retry-After": "4"}

        resp_200 = MagicMock(spec=httpx.Response)
        resp_200.status_code = 200
        resp_200.json.return_value = [{"id": "iss-1", "dns_names": ["app.example.com"]}]

        resp_empty = MagicMock(spec=httpx.Response)
        resp_empty.status_code = 200
        resp_empty.json.return_value = []

        client_mock.get.side_effect = [resp_429, resp_200, resp_empty]

        entries, truncated = fetch_certspotter_data("example.com", client=client_mock)

        assert len(entries) == 1
        assert truncated is False
        mock_sleep.assert_any_call(4.0)

    def test_certspotter_rate_limit_retry_after_over_10s_fails(self, mock_sleep):
        """Verify 429 with Retry-After > 10s aborts immediately with CertSpotterError."""
        client_mock = MagicMock(spec=httpx.Client)

        resp_429 = MagicMock(spec=httpx.Response)
        resp_429.status_code = 429
        resp_429.headers = {"Retry-After": "30"}
        client_mock.get.return_value = resp_429

        with pytest.raises(CertSpotterError, match="Retry-After=30"):
            fetch_certspotter_data("example.com", client=client_mock)

        assert client_mock.get.call_count == 1
        mock_sleep.assert_not_called()

    def test_certspotter_rate_limit_retry_fails_on_second_429(self, mock_sleep):
        """Verify 429 on second attempt after retry raises CertSpotterError."""
        client_mock = MagicMock(spec=httpx.Client)

        resp_429_1 = MagicMock(spec=httpx.Response)
        resp_429_1.status_code = 429
        resp_429_1.headers = {"Retry-After": "2"}

        resp_429_2 = MagicMock(spec=httpx.Response)
        resp_429_2.status_code = 429
        resp_429_2.headers = {"Retry-After": "2"}

        client_mock.get.side_effect = [resp_429_1, resp_429_2]

        with pytest.raises(CertSpotterError, match="rate limited .* after retry"):
            fetch_certspotter_data("example.com", client=client_mock)

        assert client_mock.get.call_count == 2
        mock_sleep.assert_called_once_with(2.0)

    def test_certspotter_page_cap_truncation(self):
        """Verify pagination stops and sets truncated=True when max_pages limit is reached."""
        client_mock = MagicMock(spec=httpx.Client)

        resp_p1 = MagicMock(spec=httpx.Response)
        resp_p1.status_code = 200
        resp_p1.json.return_value = [{"id": "1", "dns_names": ["p1.example.com"]}]

        resp_p2 = MagicMock(spec=httpx.Response)
        resp_p2.status_code = 200
        resp_p2.json.return_value = [{"id": "2", "dns_names": ["p2.example.com"]}]

        client_mock.get.side_effect = [resp_p1, resp_p2]

        entries, truncated = fetch_certspotter_data(
            "example.com", client=client_mock, max_pages=2
        )

        assert len(entries) == 2
        assert truncated is True
        assert client_mock.get.call_count == 2

    def test_certspotter_entry_cap_truncation(self):
        """Verify fetching stops and sets truncated=True when max_entries limit is reached."""
        client_mock = MagicMock(spec=httpx.Client)

        resp_p1 = MagicMock(spec=httpx.Response)
        resp_p1.status_code = 200
        resp_p1.json.return_value = [
            {"id": "1", "dns_names": ["a.example.com"]},
            {"id": "2", "dns_names": ["b.example.com"]},
            {"id": "3", "dns_names": ["c.example.com"]},
        ]
        client_mock.get.return_value = resp_p1

        entries, truncated = fetch_certspotter_data(
            "example.com", client=client_mock, max_entries=2
        )

        assert len(entries) == 2
        assert truncated is True
        assert client_mock.get.call_count == 1

    def test_certspotter_api_key_sent_as_bearer_and_not_leaked(self):
        """Verify API key is passed in Authorization header and not disclosed on error."""
        client_mock = MagicMock(spec=httpx.Client)
        secret_key = "secret_certspotter_api_key_value"

        resp_403 = MagicMock(spec=httpx.Response)
        resp_403.status_code = 403
        resp_403.text = "Forbidden: Invalid token"
        client_mock.get.return_value = resp_403

        with pytest.raises(CertSpotterError) as exc_info:
            fetch_certspotter_data(
                "example.com", client=client_mock, api_key=secret_key
            )

        # Header check
        call_headers = client_mock.get.call_args.kwargs["headers"]
        assert call_headers["Authorization"] == f"Bearer {secret_key}"

        # Error leak check
        assert secret_key not in str(exc_info.value)


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
        client_mock = MagicMock(spec=httpx.Client)
        client_mock.get.side_effect = httpx.RemoteProtocolError(
            "Server disconnected without sending a response."
        )

        with pytest.raises(CrtshError):
            fetch_crtsh_data("example.com", client=client_mock)

        assert client_mock.get.call_count == 3
