#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

from ioc_finder import find_iocs


@pytest.fixture
def text_a():
    """Provide some generic text for the tests below."""
    return 'example.com is a nice domain if you consider http://bad.com/test/bingo.php to be bad. {} {} {} 1.2.3.4 192.64.55.61 bad12312@example.org'.format('a'*32, 'b'*40, 'c'*64)


def test_ioc_finder(text_a):
    iocs = find_iocs(text_a)
    assert len(iocs['domains']) == 3
    assert 'example.com' in iocs['domains']
    assert 'example.org' in iocs['domains']
    assert 'bad.com' in iocs['domains']

    assert len(iocs['email_addresses']) == 1
    assert 'bad12312@example.org' in iocs['email_addresses']

    assert len(iocs['ipv4s']) == 2
    assert '1.2.3.4' in iocs['ipv4s']
    assert '192.64.55.61' in iocs['ipv4s']

    assert len(iocs['urls']) == 1
    assert 'http://bad.com/test/bingo.php' in iocs['urls']

    assert len(iocs['md5s']) == 1
    assert 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' in iocs['md5s']

    assert len(iocs['sha1s']) == 1
    assert 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' in iocs['sha1s']

    assert len(iocs['sha256s']) == 1
    assert 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' in iocs['sha256s']


def test_url_parsing():
    """Test some specific url examples."""
    s = "https://github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh"
    iocs = find_iocs(s)
    assert len(iocs['urls']) == 1
    assert 'https://github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh' in iocs['urls']


def test_address_email_address():
    s = "test@[192.168.2.1]"
    iocs = find_iocs(s)
    assert len(iocs['email_addresses']) == 1
    assert 'test@[192.168.2.1]' in iocs['email_addresses']
    assert len(iocs['ipv4s']) == 1
    assert '192.168.2.1' in iocs['ipv4s']

    s = "jsmith@[IPv6:2001:db8::1]"
    iocs = find_iocs(s)
    assert len(iocs['email_addresses']) == 1
    assert 'jsmith@[IPv6:2001:db8::1]' in iocs['email_addresses']
    assert len(iocs['ipv6s']) == 1
    assert '2001:db8::1' in iocs['ipv6s']


def test_address_domain_url():
    s = "http://192.64.55.61/test.php"
    iocs = find_iocs(s)
    assert len(iocs['urls']) == 1
    assert 'http://192.64.55.61/test.php' in iocs['urls']
    assert len(iocs['ipv4s']) == 1
    assert '192.64.55.61' in iocs['ipv4s']


def test_ipv4_hostname_email_address():
    s = "bad@[192.168.7.3]"
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 1
    assert '192.168.7.3' in iocs['ipv4s']
    assert len(iocs['email_addresses']) == 1
    assert 'bad@[192.168.7.3]' in iocs['email_addresses']


def test_unicode_domain_name():
    s = "ȩxample.com"
    iocs = find_iocs(s)
    assert len(iocs['domains']) == 1
    assert '\\u0229xample.com' in iocs['domains']


def test_ioc_deduplication():
    """Make sure the results returned from the ioc_finder are deduplicated."""
    iocs = find_iocs('example.com example.com')
    assert len(iocs['domains']) == 1


def test_file_hash_order():
    s = "{} {}".format('a'*32, 'b'*40)
    iocs = find_iocs(s)
    assert iocs['md5s'][0] == 'a'*32
    assert iocs['sha1s'][0] == 'b'*40


def test_url_boundaries():
    """Make sure the boundaries for a url are correct."""
    s = """http://192.168.0.1/test/bad.html</a><br></div>"""
    iocs = find_iocs(s)
    assert iocs['urls'][0] == 'http://192.168.0.1/test/bad.html'
    assert len(iocs['urls']) == 1


def test_host_parsing():
    s = "Host: dfasdfa (mz-fcb301p.ocn.ad.jp asdfsdafs"
    iocs = find_iocs(s)
    assert iocs['domains'][0] == 'mz-fcb301p.ocn.ad.jp'
    assert len(iocs['domains']) == 1

    s = "smtp.mailfrom"
    iocs = find_iocs(s)
    assert len(iocs['domains']) == 0
