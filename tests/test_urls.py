"""Test the URL parsing against the urls here: https://mathiasbynens.be/demo/url-regex."""

from d8s_lists import iterables_have_same_items

from ioc_finder import find_iocs

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
    result = find_iocs('1.1.1.1/0')
    assert result['urls'] == []

    result = find_iocs('1.1.1.1/0', parse_urls_without_scheme=False)
    assert result['urls'] == []

    result = find_iocs('1.1.1.1/0 foobar.com/test/bingo.php')
    assert result['urls'] == ['foobar.com/test/bingo.php']


def test_parse_domain_from_url_not_removing_entire_url():
    """See https://github.com/fhightower/ioc-finder/issues/90."""
    # default behaviour
    result = find_iocs('https://foobar.com/test/bingo.com/bar')
    assert iterables_have_same_items(result['domains'], ['foobar.com', 'bingo.com'])

    result = find_iocs('https://foobar.com/test/bingo.com/bar', parse_domain_from_url=False)
    assert result['domains'] == ['bingo.com']

    result = find_iocs('https://foobar.com/test/bingo.com/bar', parse_domain_from_url=False, parse_from_url_path=False)
    assert result['domains'] == []
