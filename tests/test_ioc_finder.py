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
    assert len(iocs['complete_email_addresses']) == 10
    assert 'test@a.com' in iocs['complete_email_addresses']
    assert 'bingo@en.wikipedia.com' in iocs['complete_email_addresses']
    assert 'foo@a.com' in iocs['complete_email_addresses']
    assert 'bar@b.a.com' in iocs['complete_email_addresses']
    assert 'bad@test-ing.com' in iocs['complete_email_addresses']
    assert 'me@2600.com' in iocs['complete_email_addresses']
    assert 'john.smith(comment)@example.com' in iocs['complete_email_addresses']
    assert '(comment)john.smith@example.com' in iocs['complete_email_addresses']
    assert '\"John..Doe\"@example.com' in iocs['complete_email_addresses']
    assert 'test@[192.168.0.1]' in iocs['complete_email_addresses']

    iocs = find_iocs('a@example.com')
    assert iocs['complete_email_addresses'][0] == 'a@example.com'


def test_simple_email_address_parsing():
    s = "test@a.com bingo@en.wikipedia.com foo@a.com'.format('a'*63 bar@b.a.com'.format('a'*63, 'a'*63 bad@test-ing.com me@2600.com john.smith(comment)@example.com (comment)john.smith@example.com \"John..Doe\"@example.com' test@[192.168.0.1]"

    iocs = find_iocs(s)
    assert len(iocs['email_addresses']) == 8
    assert 'test@a.com' in iocs['email_addresses']
    assert 'bingo@en.wikipedia.com' in iocs['email_addresses']
    assert 'foo@a.com' in iocs['email_addresses']
    assert 'bar@b.a.com' in iocs['email_addresses']
    assert 'bad@test-ing.com' in iocs['email_addresses']
    assert 'me@2600.com' in iocs['email_addresses']
    assert 'john.smith@example.com' in iocs['email_addresses']
    assert 'test@[192.168.0.1]' in iocs['email_addresses']

    iocs = find_iocs('a@example.com')
    assert iocs['email_addresses'][0] == 'a@example.com'


def test_url_parsing():
    invalid_urls = [
        'foo@{}.com'.format('a' * 64),
        '!@.com',
        'foo@abc',
        '@@@@-hi-.com',
        '@_hi_.com',
        'me@*hi*.com',
        'foo{}.com'.format('a' * 64),
        '.com',
        'abc',
        '-hi-.com',
        '_hi_.com',
        '*hi*.com',
    ]

    valid_urls = [
        'https://a.com',
        'https://en.wikipedia.com',
        'https://{}.com'.format('a' * 63),
        'https://{}.{}.com'.format('a' * 63, 'a' * 63),
        'https://test-ing.com',
        'https://2600.com',
        'https://example.com',
        'http://example.com',
        'ftp://example.com',
        'http://"John..Doe"@example.com',
        'http://test@a.com',
        'http://bingo@en.wikipedia.com',
        'http://foo@{}.com'.format('a' * 63),
    ]

    iocs = find_iocs(' '.join(valid_urls))
    assert len(iocs['urls']) == 13
    # make sure domains are being parsed from the valid urls as well
    assert len(iocs['domains']) == 7

    iocs = find_iocs(' '.join(invalid_urls))
    assert len(iocs['urls']) == 0


def test_file_hash_parsing():
    s = "{} {} {} {} {}".format('A' * 32, 'a' * 32, 'b' * 40, 'c' * 64, 'd' * 128)
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


def test_adsense_publisher_id_parsing():
    s = "pub-1234567891234567"
    iocs = find_iocs(s)
    assert len(iocs['google_adsense_publisher_ids']) == 1
    iocs['google_adsense_publisher_ids'][0] == 'pub-1234567891234567'

    s = "pub-1234567891234567 pub-9383614236930773"
    iocs = find_iocs(s)
    assert len(iocs['google_adsense_publisher_ids']) == 2
    iocs['google_adsense_publisher_ids'][0] == 'pub-1234567891234567'
    iocs['google_adsense_publisher_ids'][1] == 'pub-9383614236930773'


def test_analytics_publisher_id_parsing():
    s = "UA-000000-2"
    iocs = find_iocs(s)
    assert len(iocs['google_analytics_tracker_ids']) == 1
    iocs['google_analytics_tracker_ids'][0] == 'UA-000000-2'

    s = "UA-000000-2 UA-00000000-99"
    iocs = find_iocs(s)
    assert len(iocs['google_analytics_tracker_ids']) == 2
    iocs['google_analytics_tracker_ids'][0] == 'UA-000000-2'
    iocs['google_analytics_tracker_ids'][1] == 'UA-00000000-99'


def test_bitcoin_parsing():
    s = """1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.
P2SH type starting with the number 3, eg: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy.
Bech32 type starting with bc1, eg: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"""
    iocs = find_iocs(s)
    assert len(iocs['bitcoin_addresses']) == 3
    iocs['bitcoin_addresses'][0] == '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'
    iocs['bitcoin_addresses'][1] == '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'
    iocs['bitcoin_addresses'][2] == 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'


def test_xmpp_address_parsing():
    s = """foo@swissjabber.de bar@jabber.zone bom@jabber.sow.as me@example.com"""
    iocs = find_iocs(s)
    assert len(iocs['xmpp_addresses']) == 3
    iocs['xmpp_addresses'][0] == 'foo@swissjabber.de'
    iocs['xmpp_addresses'][1] == 'bar@jabber.zone'
    iocs['xmpp_addresses'][2] == 'bom@jabber.sow.as'
    assert len(iocs['domains']) == 4
    # make sure the xmpp addresses are not also parsed as email addresses
    assert len(iocs['email_addresses']) == 1

    iocs = find_iocs(s, parse_domain_name_from_xmpp_address=False)
    assert len(iocs['xmpp_addresses']) == 3
    iocs['xmpp_addresses'][0] == 'foo@swissjabber.de'
    iocs['xmpp_addresses'][1] == 'bar@jabber.zone'
    iocs['xmpp_addresses'][2] == 'bom@jabber.sow.as'
    assert len(iocs['domains']) == 1
    # make sure the xmpp addresses are not also parsed as email addresses
    assert len(iocs['email_addresses']) == 1


def test_mac_address_parsing():
    s = 'AA-F2-C9-A6-B3-4F AB:F2:C9:A6:B3:4F ACF2.C9A6.B34F'

    iocs = find_iocs(s)
    assert len(iocs['mac_addresses']) == 3
    iocs['mac_addresses'][0] == 'AA-F2-C9-A6-B3-4F'
    iocs['mac_addresses'][1] == 'AB:F2:C9:A6:B3:4F'
    iocs['mac_addresses'][2] == 'ACF2.C9A6.B34F'

    # same thing, just lower-case
    s = 'aa-f2-c9-a6-b3-4f ab:f2:c9:a6:b3:4f acf2.c9a6.b34f'
    iocs = find_iocs(s)
    assert len(iocs['mac_addresses']) == 3
    iocs['mac_addresses'][0] == 'aa-f2-c9-a6-b3-4f'
    iocs['mac_addresses'][1] == 'ab:f2:c9:a6:b3:4f'
    iocs['mac_addresses'][2] == 'acf2.c9a6.b34f'


def test_ssdeep_parsing():
    s = "1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U"
    iocs = find_iocs(s)
    assert len(iocs['ssdeeps']) == 1
    iocs['ssdeeps'][0] == '1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U'

    s = "ahdfadsfa 1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U,000/000/000000001 adfasf"
    iocs = find_iocs(s)
    assert len(iocs['ssdeeps']) == 1
    iocs['ssdeeps'][0] == '1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U'

    s = """c2b257868686c861d43c6cf3de146b8812778c8283f7d
Threat  Zepakab/Zebrocy Downloader
ssdeep  12288:QYV6MorX7qzuC3QHO9FQVHPF51jgcSj2EtPo/V7I6R+Lqaw8i6hG0:vBXu9HGaVHh4Po/VU6RkqaQ6F"""
    iocs = find_iocs(s)
    assert len(iocs['ssdeeps']) == 1
    iocs['ssdeeps'][0] == '12288:QYV6MorX7qzuC3QHO9FQVHPF51jgcSj2EtPo/V7I6R+Lqaw8i6hG0:vBXu9HGaVHh4Po/VU6RkqaQ6F'

    s = """393216:EW/eKCo9QgoHfHYebwoyC0QStQYEb+G8j3wfVOglnimQyCK+mteYREDWXKF2b:MKg3lbwoyCnCkNHlnimfCSQx8b,"000/000/000000001"
196608:AGSE26mYSK0iwH8HW9TDl0vnvCZwZEkzzeap7R:Ak28siwH8eRSn25k3eg,"000/000/000000002"
98304:O1OCzezOgr4XMP7Af0+Kh7MzplFKuu5XcS9QnCD/VWR6yf4OB6S/mwRTwjf0ih87:k/Y4XMT7YguEXqCD/VWR6yf4Ux/mwR0S,"000/000/000000003"
96:ukILJhn54RewghSib4xGEHVLFNs+4tihJW6jJenUQrsIvpMMjUg:uk0Jx54usxJHh4gJrJenUQrs2pvIg,"000/000/000000004"
196608:rNI4QlKQbWQobu0u3QRBBibfv+Z4Hjy5M+IjunAadLLtt42fAtQSqFhx:rNkK2obu0uBb3K4H28yAGc4RSax,"000/000/000000005"
1536:mFbhArcCMbR0S/kjzU6El4mUIR2JPmvY3lpKa38fTXcTns+b3tfZyCLtRs:obNCMbWpU6SzFAPV3lpCjCsQRZyQt6,"000/000/000000006"
48:CScrEd3jk5BsRSFCWfVsEWABbbpnWSgSX45dc6b5Qla9A+o5R6k7CyNRD5J:XcrEdzHRSFr9sE7XnsDe1CyNRNJ,"000/000/000000007"
24:N8Rw5AF4REesFtPP6k216xoWya1oxOKHHwa8peRK8FdigZY5tODrRRK8RfMfde8:N8Rw5AF4+XPyooa2EKnwaGeRJFYpfwzQ,"000/000/000000008"
1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U,"000/000/000000009"""
    iocs = find_iocs(s)
    print(iocs['ssdeeps'])
    assert len(iocs['ssdeeps']) == 9
    iocs['ssdeeps'][0] == '393216:EW/eKCo9QgoHfHYebwoyC0QStQYEb+G8j3wfVOglnimQyCK+mteYREDWXKF2b:MKg3lbwoyCnCkNHlnimfCSQx8b'
    iocs['ssdeeps'][1] == '196608:AGSE26mYSK0iwH8HW9TDl0vnvCZwZEkzzeap7R:Ak28siwH8eRSn25k3eg'
    iocs['ssdeeps'][2] == '98304:O1OCzezOgr4XMP7Af0+Kh7MzplFKuu5XcS9QnCD/VWR6yf4OB6S/mwRTwjf0ih87:k/Y4XMT7YguEXqCD/VWR6yf4Ux/mwR0S'
    iocs['ssdeeps'][3] == '96:ukILJhn54RewghSib4xGEHVLFNs+4tihJW6jJenUQrsIvpMMjUg:uk0Jx54usxJHh4gJrJenUQrs2pvIg'
    iocs['ssdeeps'][4] == '196608:rNI4QlKQbWQobu0u3QRBBibfv+Z4Hjy5M+IjunAadLLtt42fAtQSqFhx:rNkK2obu0uBb3K4H28yAGc4RSax'
    iocs['ssdeeps'][5] == '1536:mFbhArcCMbR0S/kjzU6El4mUIR2JPmvY3lpKa38fTXcTns+b3tfZyCLtRs:obNCMbWpU6SzFAPV3lpCjCsQRZyQt6'
    iocs['ssdeeps'][6] == '48:CScrEd3jk5BsRSFCWfVsEWABbbpnWSgSX45dc6b5Qla9A+o5R6k7CyNRD5J:XcrEdzHRSFr9sE7XnsDe1CyNRNJ'
    iocs['ssdeeps'][7] == '24:N8Rw5AF4REesFtPP6k216xoWya1oxOKHHwa8peRK8FdigZY5tODrRRK8RfMfde8:N8Rw5AF4+XPyooa2EKnwaGeRJFYpfwzQ'
    iocs['ssdeeps'][8] == '1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U'
