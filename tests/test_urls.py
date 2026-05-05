"""Test the URL parsing against the urls here: https://mathiasbynens.be/demo/url-regex."""

from d8s_lists import iterables_have_same_items

from ioc_finder import find_iocs as _find_iocs
from ioc_finder.ioc_finder import SUPPORTED_IOC_TYPES


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
