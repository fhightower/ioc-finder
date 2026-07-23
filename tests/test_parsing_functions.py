"""Make sure that the parsing functions for specific functions are imported properly."""

import pytest
from pyparsing import ParseException

from ioc_finder import parse_urls
from ioc_finder.ioc_finder import _parse_url, _remove_url_userinfo, _url_candidate_spans


def test_url_parsing_func():
    results = parse_urls("https://google.com")
    assert results == ["https://google.com"]


def test_url_candidate_spans_skip_markers_inside_expanded_span():
    text = ("a.a/" * 5000) + " https://example.com/path"

    first = text.split()[0]
    second = "https://example.com/path"
    assert list(_url_candidate_spans(text)) == [
        (0, first),
        (len(first) + 1, second),
    ]


def test_url_candidate_spans_skip_bare_ipv4_cidrs():
    """The IPv4 URL marker must not fire on bare CIDRs. Each candidate span it
    produces costs ~750µs of grammar work, and for a CIDR that work is pure
    waste — find_iocs discards the resulting "URL" in the issue-#91 removal
    pass. Netblock feeds and firewall dumps are CIDR-dense by nature, so a
    marker that fires on every one of them is a throughput cliff (2000 CIDRs:
    0.006s with the exclusion, 2.0s without)."""
    assert list(_url_candidate_spans("10.0.0.0/8 192.168.1.1/24 1.2.3.4/5")) == []

    # ...but the exclusion is narrow: only one or two digits ending the
    # whitespace-delimited token are skipped. Anything else still marks.
    assert list(_url_candidate_spans("1.2.3.4/gate.php")) == [(0, "1.2.3.4/gate.php")]
    assert list(_url_candidate_spans("1.2.3.4/80/x")) == [(0, "1.2.3.4/80/x")]
    assert list(_url_candidate_spans("1.2.3.4/12?a=b")) == [(0, "1.2.3.4/12?a=b")]
    assert list(_url_candidate_spans("1.2.3.4/123")) == [(0, "1.2.3.4/123")]
    assert list(_url_candidate_spans("10.0.0.5:8443/c2/beacon")) == [(0, "10.0.0.5:8443/c2/beacon")]


def test_parse_url_raises_on_unparseable_input():
    """`_parse_url` falls through all four URL grammars and raises."""
    with pytest.raises(ParseException, match="could not parse URL"):
        _parse_url("not a url at all")


def test_remove_url_userinfo_skips_unparseable_url():
    """A 'URL' that neither complete grammar can parse is skipped and the
    text is returned unchanged."""
    text = "some text"
    assert _remove_url_userinfo(["not a url at all"], text) == text
