"""Tests for `find_iocs(..., include_spans=True)` — the span-aware mode that
returns position information for each match in the original input text."""

import logging

import pytest

from ioc_finder import find_iocs


def _spans(result, ioc_type, value):
    """Tiny helper: pull the span list for a (type, value) pair, defaulting to
    [] so the assertion message is about the actual mismatch."""
    return result.get(ioc_type, {}).get(value, [])


def test_default_types_present_in_output():
    """Every default IOC type should appear as a key, even when empty."""
    result = find_iocs("nothing of interest here", include_spans=True)
    expected_keys = {"cves", "domains", "email_addresses", "ipv4s", "ipv6s", "md5s", "sha1s", "sha256s", "urls"}
    assert expected_keys <= set(result)


def test_domain_span_points_at_original_substring():
    text = "Visit example.com today"
    result = find_iocs(text, include_spans=True)
    spans = _spans(result, "domains", "example.com")
    assert spans == [(6, 17)]
    s, e = spans[0]
    assert text[s:e] == "example.com"


def test_fanged_domain_span_covers_brackets_in_original():
    """`example[.]com` defangs to `example.com`. The reported span must point
    at the original `example[.]com` so a caller highlighting the source text
    selects the whole defanged form."""
    text = "Visit example[.]com today"
    result = find_iocs(text, include_spans=True)
    spans = _spans(result, "domains", "example.com")
    assert spans == [(6, 19)]
    s, e = spans[0]
    assert text[s:e] == "example[.]com"


def test_ipv4_span():
    text = "the source was 192.168.1.1 yesterday"
    result = find_iocs(text, include_spans=True)
    spans = _spans(result, "ipv4s", "192.168.1.1")
    assert spans == [(15, 26)]
    assert text[15:26] == "192.168.1.1"


def test_fanged_ipv4_span_covers_brackets():
    text = "src 192[.]168[.]1[.]1 dst"
    result = find_iocs(text, include_spans=True)
    spans = _spans(result, "ipv4s", "192.168.1.1")
    assert len(spans) == 1
    s, e = spans[0]
    assert text[s:e] == "192[.]168[.]1[.]1"


def test_md5_span():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    text = f"hash: {md5} (empty file)"
    result = find_iocs(text, include_spans=True)
    spans = _spans(result, "md5s", md5)
    assert spans == [(6, 6 + len(md5))]


def test_cve_span():
    text = "tracked under CVE-2024-12345 in our system"
    result = find_iocs(text, include_spans=True)
    spans = _spans(result, "cves", "CVE-2024-12345")
    assert spans == [(14, 28)]


def test_url_span_with_trailing_quote_is_trimmed():
    """`_clean_url` strips trailing quote chars; the reported end offset must
    follow the cleaned value, not the raw match."""
    text = 'see "http://example.com/path"'
    result = find_iocs(text, include_spans=True)
    spans = _spans(result, "urls", "http://example.com/path")
    assert len(spans) == 1
    s, e = spans[0]
    assert text[s:e] == "http://example.com/path"


def test_multiple_occurrences_each_have_a_span():
    text = "1.2.3.4 talked to 1.2.3.4 again"
    result = find_iocs(text, include_spans=True)
    spans = _spans(result, "ipv4s", "1.2.3.4")
    assert spans == [(0, 7), (18, 25)]


def test_email_span():
    text = "contact alice@example.com for details"
    result = find_iocs(text, include_spans=True)
    spans = _spans(result, "email_addresses", "alice@example.com")
    assert len(spans) == 1
    s, e = spans[0]
    assert text[s:e] == "alice@example.com"


def test_ipv6_span():
    text = "host 2001:db8::1 went down"
    result = find_iocs(text, include_spans=True)
    spans = _spans(result, "ipv6s", "2001:db8::1")
    assert len(spans) == 1
    s, e = spans[0]
    assert text[s:e] == "2001:db8::1"


def test_non_default_type_with_include_spans_raises():
    """Out of scope for the first cut — surface the limitation explicitly
    instead of returning silently incomplete data."""
    with pytest.raises(ValueError, match="include_spans=True"):
        find_iocs("something", include_spans=True, included_ioc_types=["bitcoin_addresses"])


def test_spans_subset_of_default_types_is_ok():
    """Restricting to a subset of the defaults is allowed — only mixing in
    non-default types should raise."""
    text = "hit 8.8.8.8 over CVE-2020-1234"
    result = find_iocs(text, include_spans=True, included_ioc_types=["ipv4s", "cves"])
    assert set(result) == {"ipv4s", "cves"}
    assert _spans(result, "ipv4s", "8.8.8.8") == [(4, 11)]
    assert _spans(result, "cves", "CVE-2020-1234") == [(17, 30)]


def test_default_mode_unchanged():
    """Sanity check that `include_spans=False` (default) still returns the
    legacy list-of-strings shape."""
    text = "ping 1.1.1.1"
    result = find_iocs(text)
    assert result["ipv4s"] == ["1.1.1.1"]


def test_url_removal_when_neither_domain_nor_path_wanted():
    """`parse_domain_from_url=False, parse_from_url_path=False` — entire URL
    pieces should be wiped from the working text so nothing inside them gets
    surfaced as a domain. The URL itself still appears in the output."""
    text = "see http://hidden.example.com/path/to/resource for more"
    result = find_iocs(
        text,
        include_spans=True,
        parse_domain_from_url=False,
        parse_from_url_path=False,
    )
    assert _spans(result, "urls", "http://hidden.example.com/path/to/resource")
    assert _spans(result, "domains", "hidden.example.com") == []


def test_url_domain_removed_but_path_parsed():
    """`parse_domain_from_url=False, parse_from_url_path=True` (default for
    path) — the URL's authority should be wiped, but path content (e.g. a
    domain mentioned inside the path) is still scanned."""
    text = "url http://outer.example.com/inner.example.org/x end"
    result = find_iocs(
        text,
        include_spans=True,
        parse_domain_from_url=False,
    )
    assert _spans(result, "domains", "outer.example.com") == []
    inner_spans = _spans(result, "domains", "inner.example.org")
    assert len(inner_spans) == 1


def test_url_path_removed_but_domain_parsed():
    """`parse_from_url_path=False` — the URL path is wiped so nothing inside
    surfaces, but the URL's domain is still surfaced as a domain match."""
    text = "url http://keep.example.com/strip.example.org/x end"
    result = find_iocs(
        text,
        include_spans=True,
        parse_from_url_path=False,
    )
    assert _spans(result, "domains", "keep.example.com")
    assert _spans(result, "domains", "strip.example.org") == []


def test_email_domain_removal_branch():
    """`parse_domain_from_email_address=False` — the email's domain shouldn't
    leak out as a separate domain match."""
    text = "ping alice@unique-host.com for more"
    result = find_iocs(
        text,
        include_spans=True,
        parse_domain_from_email_address=False,
    )
    assert _spans(result, "email_addresses", "alice@unique-host.com")
    assert _spans(result, "domains", "unique-host.com") == []


def test_xmpp_domain_removal_branch():
    """`parse_domain_name_from_xmpp_address=False` — the xmpp address itself
    isn't a default IOC type, but its domain shouldn't leak out either."""
    text = "ping bob@chat.jabber.com for xmpp"
    result = find_iocs(
        text,
        include_spans=True,
        parse_domain_name_from_xmpp_address=False,
    )
    assert _spans(result, "domains", "chat.jabber.com") == []


def test_xmpp_local_part_does_not_become_email_with_default_flag():
    """With the default `parse_domain_name_from_xmpp_address=True`, the xmpp
    local part still gets stripped from the email scan so it isn't double-
    counted. The xmpp address's domain is still parseable as a domain."""
    text = "see bob@chat.jabber.com today"
    result = find_iocs(text, include_spans=True)
    assert _spans(result, "email_addresses", "bob@chat.jabber.com") == []
    assert _spans(result, "domains", "chat.jabber.com")


def test_multi_char_fanged_replacement_offset_map():
    """`hxxp` defangs to `http` — a 4-char-to-4-char replacement that
    SequenceMatcher decomposes into a multi-char non-equal opcode,
    exercising the interior-position branch in `_build_fang_offset_maps`."""
    text = "go to hxxp://example.com/page now"
    result = find_iocs(text, include_spans=True)
    spans = _spans(result, "urls", "http://example.com/page")
    assert len(spans) == 1
    s, e = spans[0]
    # Span should cover the original `hxxp://example.com/page`.
    assert text[s:e] == "hxxp://example.com/page"


def test_logger_debug_path_runs(caplog):
    """Coverage for the debug-log line in the span pipeline — mirrors the
    matching line in the non-span flow."""
    with caplog.at_level(logging.DEBUG, logger="ioc_finder"):
        find_iocs("see 1.2.3.4", include_spans=True)
    assert any("span mode" in m for m in caplog.messages)


def test_consecutive_fanged_segments_offset_map():
    """Exercises the interior-loop branch in `_build_fang_offset_maps` where
    a single non-equal opcode spans more than one fanged char.

    `a[.][.]b.com` defangs to `a..b.com`. The domain-candidate regex requires
    a label between dots, so the empty middle segment breaks the run and the
    parser surfaces only `b.com` — but we still verify the span points back
    at the corresponding original-text substring."""
    text = "Visit a[.][.]b.com today"
    result = find_iocs(text, include_spans=True)
    spans = _spans(result, "domains", "b.com")
    assert len(spans) == 1
    s, e = spans[0]
    assert text[s:e] == "b.com"
