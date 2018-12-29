#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ioc_finder import find_iocs


def test_domain_parsing():
    s = "this is just a (google.com) test of example.com"
    iocs = find_iocs(s)
    assert len(iocs['domains']) == 2
    assert 'google.com' in iocs['domains']


def test_ipv4_parsing():
    s = "this is just a (1.2.3.54) test of 255.255.1.255 255.256.344.1"
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 2
    assert '1.2.3.54' in iocs['ipv4s']
    assert '255.255.1.255' in iocs['ipv4s']
    assert '255.256.344.1' not in iocs['ipv4s']


def test_ipv6_parsing():
    s = "2001:0db8:0000:0000:0000:ff00:0042:8329 testing 2001:db8:0:0:0:ff00:42:8329 shfaldkafsdfa 2001:db8::ff00:42:8329 asdfadfas afkj;fl ::1 kljfkadf 1:1"
    iocs = find_iocs(s)
    assert len(iocs['ipv6s']) == 5
    # TODO: the following 3 ipv6s addresses are the same representation of the same thing; I need to deduplicate these more thoroughly in the parsing function
    assert '2001:0db8:0000:0000:0000:ff00:0042:8329' in iocs['ipv6s']
    assert '2001:db8:0:0:0:ff00:42:8329' in iocs['ipv6s']
    assert '2001:db8::ff00:42:8329' in iocs['ipv6s']
    assert '::1' in iocs['ipv6s']
    # assert '1:1' not in iocs['ipv6s']


def test_email_address_parsing():
    s = "test@a.com bingo@en.wikipedia.com foo@a.com'.format('a'*63 bar@b.a.com'.format('a'*63, 'a'*63 bad@test-ing.com me@2600.com john.smith(comment)@example.com (comment)john.smith@example.com \"John..Doe\"@example.com' test@[192.168.0.1]"

    iocs = find_iocs(s)
    assert len(iocs['email_addresses']) == 10
    assert 'test@a.com' in iocs['email_addresses']
    assert 'bingo@en.wikipedia.com' in iocs['email_addresses']
    assert 'foo@a.com' in iocs['email_addresses']
    assert 'bar@b.a.com' in iocs['email_addresses']
    assert 'bad@test-ing.com' in iocs['email_addresses']
    assert 'me@2600.com' in iocs['email_addresses']
    assert 'john.smith(comment)@example.com' in iocs['email_addresses']
    assert '(comment)john.smith@example.com' in iocs['email_addresses']
    assert '\"John..Doe\"@example.com' in iocs['email_addresses']
    assert 'test@[192.168.0.1]' in iocs['email_addresses']

    iocs = find_iocs('a@example.com')
    assert iocs['email_addresses'][0] == 'a@example.com'


def test_simple_email_address_parsing():
    s = "test@a.com bingo@en.wikipedia.com foo@a.com'.format('a'*63 bar@b.a.com'.format('a'*63, 'a'*63 bad@test-ing.com me@2600.com john.smith(comment)@example.com (comment)john.smith@example.com \"John..Doe\"@example.com' test@[192.168.0.1]"

    iocs = find_iocs(s)
    assert len(iocs['simple_email_addresses']) == 8
    assert 'test@a.com' in iocs['simple_email_addresses']
    assert 'bingo@en.wikipedia.com' in iocs['simple_email_addresses']
    assert 'foo@a.com' in iocs['simple_email_addresses']
    assert 'bar@b.a.com' in iocs['simple_email_addresses']
    assert 'bad@test-ing.com' in iocs['simple_email_addresses']
    assert 'me@2600.com' in iocs['simple_email_addresses']
    assert 'john.smith@example.com' in iocs['simple_email_addresses']
    assert 'test@[192.168.0.1]' in iocs['simple_email_addresses']

    iocs = find_iocs('a@example.com')
    assert iocs['simple_email_addresses'][0] == 'a@example.com'


def test_url_parsing():
    invalid_urls = [
        'foo@{}.com'.format('a'*64),
        '!@.com',
        'foo@abc',
        '@@@@-hi-.com',
        '@_hi_.com',
        'me@*hi*.com',
        'foo{}.com'.format('a'*64),
        '.com',
        'abc',
        '-hi-.com',
        '_hi_.com',
        '*hi*.com'
    ]

    valid_urls = [
        'https://a.com',
        'https://en.wikipedia.com',
        'https://{}.com'.format('a'*63),
        'https://{}.{}.com'.format('a'*63, 'a'*63),
        'https://test-ing.com',
        'https://2600.com',
        'https://example.com',
        'http://example.com',
        'ftp://example.com',
        'http://"John..Doe"@example.com',
        'http://test@a.com',
        'http://bingo@en.wikipedia.com',
        'http://foo@{}.com'.format('a'*63),
    ]

    iocs = find_iocs(' '.join(valid_urls))
    assert len(iocs['urls']) == 13
    # make sure hosts are being parsed from the valid urls as well
    assert len(iocs['domains']) == 7

    iocs = find_iocs(' '.join(invalid_urls))
    assert len(iocs['urls']) == 0


def test_file_hash_parsing():
    s = "{} {} {} {} {}".format('A'*32, 'a'*32, 'b'*40, 'c'*64, 'd'*128)
    iocs = find_iocs(s)
    assert len(iocs['md5s']) == 1
    assert len(iocs['sha1s']) == 1
    assert len(iocs['sha256s']) == 1
    assert len(iocs['sha512s']) == 1


def test_asn_parsing():
    s = "asn1234 as1234 asn 1234 as 1234 AS 4321 ASN4321"
    iocs = find_iocs(s)
    # this test works because all of the asns should be standardized into the same form
    assert len(iocs['asns']) == 2
    assert 'ASN1234' in iocs['asns']
    assert 'ASN4321' in iocs['asns']


def test_cve_parsing():
    s = "cve-2014-290902 cve 2014-290902 cve-1999-2909023422 cve 2999-290902 CVE 1928-290902"
    iocs = find_iocs(s)
    assert len(iocs['cves']) == 4
    assert 'CVE-2014-290902' in iocs['cves']
    assert 'CVE-1928-290902' in iocs['cves']


def test_ipv4_cidr_parsing():
    s = "1.2.3.4/0 1.2.3.4/10 1.2.3.4/20 1.2.3.4/32"
    iocs = find_iocs(s)
    assert len(iocs['ipv4_cidrs']) == 4
    assert '1.2.3.4/0' in iocs['ipv4_cidrs']
    assert '1.2.3.4/10' in iocs['ipv4_cidrs']
    assert '1.2.3.4/20' in iocs['ipv4_cidrs']
    assert '1.2.3.4/32' in iocs['ipv4_cidrs']


def test_registry_key_parsing():
    s = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows HKLM\Software\Microsoft\Windows HKCC\Software\Microsoft\Windows"
    iocs = find_iocs(s)
    assert len(iocs['registry_key_paths']) == 3
    print("iocs {}".format(iocs))
    assert 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows' in iocs['registry_key_paths']
    assert 'HKLM\Software\Microsoft\Windows' in iocs['registry_key_paths']
    assert 'HKCC\Software\Microsoft\Windows' in iocs['registry_key_paths']
