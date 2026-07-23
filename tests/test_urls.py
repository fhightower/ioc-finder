"""Test the URL parsing against the urls here: https://mathiasbynens.be/demo/url-regex."""

import pytest
from d8s_lists import iterables_have_same_items
from pyparsing import ParseException

from ioc_finder import find_iocs as _find_iocs
from ioc_finder import parse_urls
from ioc_finder.ioc_finder import SUPPORTED_IOC_TYPES, _parse_url, _remove_url_userinfo
from ioc_finder.ioc_grammars import scheme_less_url


def find_iocs(*args, **kwargs):
    kwargs.setdefault("included_ioc_types", SUPPORTED_IOC_TYPES)
    return _find_iocs(*args, **kwargs)


# VALID_URLS = [
#     'http://foo.com/blah_blah',
#     'http://foo.com/blah_blah/',
#     'http://foo.com/blah_blah_(wikipedia)',
#     'http://foo.com/blah_blah_(wikipedia)_(again)',
#     'http://www.example.com/wpstyle/?p=364',
#     'https://www.example.com/foo/?bar=baz&inga=42&quux',
#     'http://✪df.ws/123',
#     'http://userid:password@example.com:8080',
#     'http://userid:password@example.com:8080/',
#     'http://userid@example.com',
#     'http://userid@example.com/',
#     'http://userid@example.com:8080',
#     'http://userid@example.com:8080/',
#     'http://userid:password@example.com',
#     'http://userid:password@example.com/',
#     'http://142.42.1.1/',
#     'http://142.42.1.1:8080/',
#     'http://➡.ws/䨹',
#     'http://⌘.ws',
#     'http://⌘.ws/',
#     'http://foo.com/blah_(wikipedia)#cite-1',
#     'http://foo.com/blah_(wikipedia)_blah#cite-1',
#     'http://foo.com/unicode_(✪)_in_parens',
#     'http://foo.com/(something)?after=parens',
#     'http://☺.damowmow.com/',
#     'http://code.google.com/events/#&product=browser',
#     'http://j.mp',
#     'ftp://foo.bar/baz',
#     'http://foo.bar/?q=Test%20URL-encoded%20stuff',
#     'http://مثال.إختبار',
#     'http://例子.测试',
#     'http://उदाहरण.परीक्षा',
#     "http://-.~_!$&'()*+,;=:%40:80%2f::::::@example.com",
#     'http://1337.net',
#     'http://a.b-c.de',
#     'http://223.255.255.254',
# ]


# def test_url_parsing():
#     for url in VALID_URLS:
#         iocs = find_iocs(url)
#         try:
#             assert len(iocs['urls']) == 1
#             assert iocs['urls'][0] == url
#         except AssertionError as e:
#             print('failed on url: {}'.format(url))
#             raise e


# INVALID_URLS = [
#     'http://',
#     'http://.',
#     'http://..',
#     'http://../',
#     'http://?',
#     'http://??',
#     'http://??/',
#     'http://#',
#     'http://##',
#     'http://##/',
#     '//',
#     '//a',
#     '///a',
#     '///',
#     'http:///a',
#     'foo.com',
#     'rdar://1234',
#     'h://test',
#     ':// should fail',
#     'ftps://foo.bar/',
#     'http://-error-.invalid/',
#     'http://a.b--c.de/',
#     'http://-a.b.co',
#     'http://a.b-.co',
#     'http://0.0.0.0',
#     'http://10.1.1.0',
#     'http://10.1.1.255',
#     'http://224.1.1.1',
#     'http://1.1.1.1.1',
#     'http://123.123.123',
#     'http://3628126748',
#     'http://.www.foo.bar/',
#     'http://www.foo.bar./',
#     'http://.www.foo.bar./',
#     'http://10.1.1.1',
# ]


# def test_invalid_urls():
#     for url in INVALID_URLS:
#         iocs = find_iocs(url)
#         assert len(iocs['urls']) == 0


def test_cidr_ranges_not_found_as_urls():
    """See https://github.com/fhightower/ioc-finder/issues/91."""
    result = find_iocs("1.1.1.1/0")
    assert result["urls"] == []

    result = find_iocs("1.1.1.1/0", parse_urls_without_scheme=False)
    assert result["urls"] == []

    result = find_iocs("1.1.1.1/0 foobar.com/test/bingo.php")
    assert result["urls"] == ["foobar.com/test/bingo.php"]


def test_cidr_ranges_not_found_as_urls__issue_260():
    """See https://github.com/fhightower/ioc-finder/issues/260."""
    cidrs = [
        "85.93.4.0/25",
        "85.93.39.32/27",
        "85.93.4.192/27",
        "85.93.40.0/21",
        "85.93.0.116/31",
        "85.93.39.16/28",
        "85.93.3.224/27",
        "85.93.4.236/31",
        "85.93.39.128/25",
        "85.93.48.0/24",
        "85.93.49.128/28",
        "85.93.49.0/25",
        "85.93.4.128/26",
        "85.93.0.112/30",
        "85.93.39.64/26",
        "85.93.0.96/28",
        "85.93.39.8/29",
        "85.93.49.144/31",
        "85.93.0.2/31",
        "85.93.4.232/30",
        "85.93.0.92/30",
        "85.93.4.224/29",
    ]
    text = " ".join(cidrs)

    result = find_iocs(text)
    assert result["urls"] == []
    assert result["urls_complete"] == []
    assert iterables_have_same_items(result["ipv4_cidrs"], cidrs)


def test_parse_domain_from_url_not_removing_entire_url():
    """See https://github.com/fhightower/ioc-finder/issues/90."""
    # default behaviour
    result = find_iocs("https://foobar.com/test/bingo.com/bar")
    assert iterables_have_same_items(result["domains"], ["foobar.com", "bingo.com"])

    result = find_iocs("https://foobar.com/test/bingo.com/bar", parse_domain_from_url=False)
    assert result["domains"] == ["bingo.com"]

    result = find_iocs("https://foobar.com/test/bingo.com/bar", parse_domain_from_url=False, parse_from_url_path=False)
    assert result["domains"] == []


def test_parse_domain_from_url__userinfo_url():
    """Exercise the complete URL parser fallback when userinfo is present."""
    result = find_iocs(
        "https://user:pass@example.com/path",
        parse_domain_from_url=False,
        parse_urls_without_scheme=False,
    )
    assert result["urls_complete"] == ["https://user:pass@example.com/path"]
    assert result["domains"] == []


def test_urls_complete__at_sign_in_path():
    """The complete URL grammar should accept "@" in the path per RFC 3986 pchar."""
    result = find_iocs(
        "Check https://example.com/users/@alice for details",
        parse_urls_without_scheme=False,
    )
    assert result["urls_complete"] == ["https://example.com/users/@alice"]

    result = find_iocs(
        "https://api.example.com/v1/@user/profile.json and https://gitlab.com/group/proj/-/issues/@me",
        parse_urls_without_scheme=False,
    )
    assert iterables_have_same_items(
        result["urls_complete"],
        [
            "https://api.example.com/v1/@user/profile.json",
            "https://gitlab.com/group/proj/-/issues/@me",
        ],
    )


def test_issue_104__encoded_url_properly_parsed():
    s = "https://asf.goole.com/mail?url=http%3A%2F%2Ffreasdfuewriter.com%2Fcs%2Fimage%2FCommerciaE.jpg&t=1575955624&ymreqid=733bc9eb-e8f-34cb-1cb5-120010019e00&sig=x2Pa2oOYxanG52s4vyCEFg--~Chttp://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip"
    result = find_iocs(s)
    assert result["urls"] == [
        "https://asf.goole.com/mail?url=http%3A%2F%2Ffreasdfuewriter.com%2Fcs%2Fimage%2FCommerciaE.jpg&t=1575955624&ymreqid=733bc9eb-e8f-34cb-1cb5-120010019e00&sig=x2Pa2oOYxanG52s4vyCEFg--~Chttp://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip"
    ]


def test_url__percent_encoded_path():
    # make sure a percent encoded path is properly removed so that nothing is parsed from it
    s = "https://example.com/test%20page/foo.com/bingo.php?q=bar.com"
    result = find_iocs(s, parse_from_url_path=False)
    assert result["urls"] == ["https://example.com/test%20page/foo.com/bingo.php?q=bar.com"]
    assert iterables_have_same_items(
        result["domains"], ["example.com", "bar.com"]
    )  # the key here is that "foo.com" is not parsed because it is part of the path (which has been removed)
    assert result["file_paths"] == []


def test_scheme_ful_url_does_not_surface_twice():
    """See https://github.com/fhightower/ioc-finder/issues/244. A scheme-ful URL
    must not also surface as a scheme-less URL via the offset right after
    `://`."""
    result = find_iocs("https://example.com/path")
    assert result["urls"] == ["https://example.com/path"]


def test_scheme_less_url_after_scheme_ful_url():
    result = find_iocs("https://a.com foo.com/bar")
    assert iterables_have_same_items(result["urls"], ["https://a.com", "foo.com/bar"])


def test_embedded_url_in_query_does_not_surface_separately():
    """A scheme-less host/path embedded in a scheme-ful URL's query string must
    not be matched as a second URL."""
    result = find_iocs("Visit https://shortener.com/?url=foo.com/bar")
    assert result["urls"] == ["https://shortener.com/?url=foo.com/bar"]


def test_scheme_less_url_dedup():
    result = find_iocs("foo.com/bar foo.com/bar")
    assert result["urls"] == ["foo.com/bar"]


def test_scheme_less_url_grammar_rejects_scheme_ful_input():
    with pytest.raises(ParseException):
        scheme_less_url.parse_string("https://foo.com/bar")


def test_scheme_less_url_grammar_accepts_bare_input():
    parsed = scheme_less_url.parse_string("foo.com/bar")
    assert parsed[0] == "foo.com/bar"


def test_scheme_less_url_grammar_still_finds_parenthesised_match():
    """A punctuation-delimited scheme-less URL is found, starting right after
    the opening `(`."""
    matches = list(scheme_less_url.scan_string("(foo.com/bar)"))
    assert len(matches) == 1
    tokens, start, _ = matches[0]
    assert tokens[0].startswith("foo.com/bar")
    assert start == 1


def test_slash_preceded_scheme_less_url_still_found():
    """A scheme-less URL whose host is preceded by a bare `/` must still be
    found. The scheme-ful URL masking pass (not a grammar start boundary) is
    what prevents scheme-ful URLs from re-surfacing, so a leading `/` here is
    harmless. See PR #369 review thread."""
    assert find_iocs("path/to/foo.com/bar")["urls"] == ["foo.com/bar"]


def test_scheme_ful_substring_does_not_leak_scheme_less_match():
    """Masking a scheme-ful URL must blank its exact character span, not every
    occurrence of its match text. A shorter scheme-ful URL whose text is a
    prefix of a longer one previously caused `str.replace` to punch a hole in
    the longer URL, leaking a spurious scheme-less match from the remainder.
    See PR #369 review thread."""
    result = find_iocs("see http://a.com or http://a.com?u=b.co/x for more")
    assert iterables_have_same_items(result["urls"], ["http://a.com", "http://a.com?u=b.co/x"])
    assert "b.co/x" not in result["urls"]


def test_embedded_url_in_query_not_found_when_scheme_less_disabled():
    """With parse_urls_without_scheme=False only the scheme-ful URL is parsed,
    so the embedded scheme-less host in its query never surfaces."""
    result = find_iocs(
        "Visit https://shortener.com/?url=foo.com/bar",
        parse_urls_without_scheme=False,
    )
    assert result["urls"] == ["https://shortener.com/?url=foo.com/bar"]


def test_parse_url_helper_handles_scheme_ful_and_scheme_less():
    parsed = _parse_url("https://example.com/path")
    authority = parsed.url_authority
    if not isinstance(authority, str):
        authority = authority[0]
    assert authority == "example.com"

    parsed = _parse_url("example.com/path")
    authority = parsed.url_authority
    if not isinstance(authority, str):
        authority = authority[0]
    assert authority == "example.com"


def test_remove_url_userinfo_works_for_scheme_ful_url():
    stripped = _remove_url_userinfo(
        ["http://userid:password@example.com/"],
        "http://userid:password@example.com/",
    )
    assert "userid:password@" not in stripped


def test_scheme_less_url_with_port_is_found():
    """A scheme-less URL with an explicit port must be found. The
    `_URL_MARKER_RE` prefilter previously only recognized `://` and `.tld/`
    markers, so `.tld:port/` spans were never handed to the (accepting)
    scheme_less_url grammar."""
    result = find_iocs("visit example.com:8080/admin now")
    assert result["urls"] == ["example.com:8080/admin"]


def test_scheme_less_url_with_ipv4_host_is_found():
    """A scheme-less URL with an IPv4 host must be found. The `.tld/` marker
    requires a letter after the dot, so `1.2.3.4/gate.php` spans were never
    handed to the (accepting) scheme_less_url grammar."""
    result = find_iocs("panel at 1.2.3.4/gate.php here")
    assert result["urls"] == ["1.2.3.4/gate.php"]


def test_scheme_less_url_with_ipv4_host_and_port_is_found():
    result = find_iocs("callback to 10.0.0.5:8443/c2/beacon channel")
    assert result["urls"] == ["10.0.0.5:8443/c2/beacon"]


def test_scheme_less_url_port_is_not_capped_below_the_grammar():
    """The marker must stay a superset of the grammar it gates. `port` is
    `Word(":", nums, min=2)` — unbounded — so capping the marker's port at the
    five digits a real TCP port needs would make these unreachable while the
    scheme-*ful* spelling still parsed (the `://` marker never looks at the
    port), i.e. the same authority would parse or not depending on whether a
    scheme was present."""
    assert parse_urls("example.com:123456/x") == ["example.com:123456/x"]
    assert parse_urls("http://example.com:123456/x") == ["http://example.com:123456/x"]
    assert parse_urls("1.2.3.4:123456/x") == ["1.2.3.4:123456/x"]


def test_ipv4_cidrs_still_not_found_as_urls_with_ipv4_url_marker():
    """The IPv4 URL marker must not turn CIDRs into URLs. It excludes the
    bare-CIDR shape outright, so these never even become candidate spans; the
    CIDR removal pass in find_iocs (issue #91) is the second line of defense."""
    result = find_iocs("1.1.1.1/0 and 10.0.0.0/8")
    assert result["urls"] == []
    assert iterables_have_same_items(result["ipv4_cidrs"], ["1.1.1.1/0", "10.0.0.0/8"])


def test_bare_ipv4_cidrs_do_not_become_url_candidates():
    """The bare-CIDR exclusion in `_URL_MARKER_RE` keeps netblock-dense text
    off the grammar's slow path: a candidate span costs ~750µs of grammar work
    that find_iocs then discards. `parse_urls` (which has no CIDR removal pass)
    is the direct observation point."""
    assert parse_urls("10.0.0.0/8") == []
    assert parse_urls("192.168.1.1/24") == []
    # ...but anything past the prefix-length digits is still a URL candidate.
    assert parse_urls("1.2.3.4/80/x") == ["1.2.3.4/80/x"]
    assert parse_urls("1.2.3.4/12?a=b") == ["1.2.3.4/12?a=b"]
    assert parse_urls("1.2.3.4/123") == ["1.2.3.4/123"]
