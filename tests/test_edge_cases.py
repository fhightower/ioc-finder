#!/usr/bin/env python3

import pytest

from ioc_finder import find_iocs


@pytest.fixture
def text_a():
    """Provide some generic text for the tests below."""
    return "example.com is a nice domain if you consider http://bad.com/test/bingo.php to be bad. {} {} {} 1.2.3.4 192.64.55.61 bad12312@example.org".format(
        "a" * 32, "b" * 40, "c" * 64
    )


def test_domain_name_with_underscore():
    # see https://github.com/fhightower/ioc-finder/issues/26
    s = "o_o.lgms.nl"
    results = find_iocs(s)
    assert results["domains"] == ["o_o.lgms.nl"]

    s = "_jabber._tcp.gmail.com"
    results = find_iocs(s)
    assert results["domains"] == ["_jabber._tcp.gmail.com"]


def test_url_with_underscore_in_subdomain():
    # see https://github.com/fhightower/ioc-finder/issues/26
    s = "https://o_o.lgms.nl/"
    results = find_iocs(s)
    assert results["urls"] == ["https://o_o.lgms.nl/"]


def test_ioc_finder(text_a):
    iocs = find_iocs(text_a)
    assert len(iocs["domains"]) == 3
    assert "example.com" in iocs["domains"]
    assert "example.org" in iocs["domains"]
    assert "bad.com" in iocs["domains"]

    assert iocs["email_addresses_complete"] == ["bad12312@example.org"]

    assert len(iocs["ipv4s"]) == 2
    assert "1.2.3.4" in iocs["ipv4s"]
    assert "192.64.55.61" in iocs["ipv4s"]

    assert iocs["urls"] == ["http://bad.com/test/bingo.php"]
    assert iocs["md5s"] == ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    assert iocs["sha1s"] == ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
    assert iocs["sha256s"] == ["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]


def test_url_parsing():
    """Test some specific url examples."""
    s = "https://github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh"
    iocs = find_iocs(s)
    assert iocs["urls"] == ["https://github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh"]

    s = '<link href="http://fonts.googleapis.com/css?family=Lato:400,700" rel="stylesheet" type="text/css"/>'
    iocs = find_iocs(s)
    assert "http://fonts.googleapis.com/css?family=Lato:400,700" in iocs["urls"]

    s = '<link href="http://fonts.googleapis.com/css?family=Lato:400,700" rel="stylesheet" type="text/css"/>'
    iocs = find_iocs(s)
    assert "http://fonts.googleapis.com/css?family=Lato:400,700" in iocs["urls"]

    s = '<a href="https://bit.ly/12345#abcd" target="_blank" style="text-decoration:none;;">'
    results = find_iocs(s)
    assert results["urls"] == ["https://bit.ly/12345#abcd"]

    s = '<a href="https://bit.ly/12345" target="_blank" style="text-decoration:none;;">'
    results = find_iocs(s)
    assert results["urls"] == ["https://bit.ly/12345"]

    s = '<a href="https://bit.ly" target="_blank" style="text-decoration:none;;">'
    results = find_iocs(s)
    assert results["urls"] == ["https://bit.ly"]

    s = '<a href="https://bit.ly/" target="_blank" style="text-decoration:none;;">'
    results = find_iocs(s)
    assert results["urls"] == ["https://bit.ly/"]

    s = "http://example.com//test"
    results = find_iocs(s)
    assert results["urls"] == ["http://example.com//test"]


def test_issue_45_url_parsing():
    s = "http://wmfolcs3.pn.4y.nv.kr2x1dt.net/gz+/(y%40%26//%3c7aew%5cqv%0a/%0bcz,r/r%5c%7b/7re//6%3e/f%23%7ce0p'6_%09/d%5c"
    results = find_iocs(s)
    assert results["urls"] == [
        "http://wmfolcs3.pn.4y.nv.kr2x1dt.net/gz+/(y%40%26//%3c7aew%5cqv%0a/%0bcz,r/r%5c%7b/7re//6%3e/f%23%7ce0p'6_%09/d%5c"
    ]


def test_schemeless_url_parsing():
    """Test parsing URLs without a scheme."""
    s = "github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh"
    iocs = find_iocs(s)
    assert iocs["urls"] == ["github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh"]

    s = "github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh hightower.space/projects"
    iocs = find_iocs(s)
    assert len(iocs["urls"]) == 2
    assert "hightower.space/projects" in iocs["urls"]
    assert "github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh" in iocs["urls"]

    s = "https://github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh hightower.space/projects"
    iocs = find_iocs(s, parse_urls_without_scheme=False)
    assert iocs["urls"] == ["https://github.com/StylishThemes/GitHub-Dark/blob/master/tools/authors.sh"]


def test_address_email_address():
    s = ">test@[192.168.2.1]<"
    iocs = find_iocs(s)
    assert iocs["email_addresses_complete"] == ["test@[192.168.2.1]"]
    assert iocs["email_addresses"] == ["test@[192.168.2.1]"]
    assert iocs["ipv4s"] == ["192.168.2.1"]

    s = "bad@[192.168.7.3]"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == ["192.168.7.3"]
    assert iocs["email_addresses_complete"] == ["bad@[192.168.7.3]"]
    assert iocs["email_addresses"] == ["bad@[192.168.7.3]"]

    s = "bad@[192.168.7.3]aaaaa"
    iocs = find_iocs(s)
    assert iocs["email_addresses_complete"] == ["bad@[192.168.7.3]"]
    assert iocs["email_addresses"] == ["bad@[192.168.7.3]"]

    s = "jsmith@[IPv6:2001:db8::1]"
    iocs = find_iocs(s)
    assert iocs["email_addresses_complete"] == ["jsmith@[IPv6:2001:db8::1]"]
    assert iocs["email_addresses"] == ["jsmith@[IPv6:2001:db8::1]"]
    assert iocs["ipv6s"] == ["2001:db8::1"]


def test_address_domain_url():
    s = "http://192.64.55.61/test.php"
    iocs = find_iocs(s)
    assert iocs["urls"] == ["http://192.64.55.61/test.php"]
    assert iocs["ipv4s"] == ["192.64.55.61"]


def test_url_domain_name_parsing():
    s = "http://foo.youtube/test.php"
    iocs = find_iocs(s)
    assert iocs["urls"] == ["http://foo.youtube/test.php"]
    assert iocs["domains"] == ["foo.youtube"]


def test_ioc_deduplication():
    """Make sure the results returned from the ioc_finder are deduplicated."""
    iocs = find_iocs("example.com example.com")
    assert iocs["domains"] == ["example.com"]


def test_file_hash_order():
    s = "{} {}".format("a" * 32, "b" * 40)
    iocs = find_iocs(s)
    assert iocs["md5s"][0] == "a" * 32
    assert iocs["sha1s"][0] == "b" * 40


def test_file_hash_parsing():
    s = "this is a test{}".format("a" * 32)
    iocs = find_iocs(s)
    assert iocs["md5s"] == []

    s = "this is a test {}".format("a" * 32)
    iocs = find_iocs(s)
    assert iocs["md5s"] == ["a" * 32]

    s = 'this is a test "{}"'.format("a" * 32)
    iocs = find_iocs(s)
    assert iocs["md5s"] == ["a" * 32]

    s = "this is a test {}.".format("a" * 32)
    iocs = find_iocs(s)
    assert iocs["md5s"] == ["a" * 32]

    s = "0x1a1db93766e31994507511c9c70a1dd94465cf6d"
    iocs = find_iocs(s)
    assert iocs["sha1s"] == ["1a1db93766e31994507511c9c70a1dd94465cf6d"]


def test_url_boundaries():
    """Make sure the boundaries for a url are correct."""
    s = """http://192.168.0.1/test/bad.html</a><br></div>"""
    iocs = find_iocs(s)
    assert iocs["urls"] == ["http://192.168.0.1/test/bad.html"]

    s = """<IMg SRc="https://i.imgur.com/abc.png#4827766048"/><br>
<IMg SRc="https://i.imgur.com/def.png#4827766048"/><br>"""
    iocs = find_iocs(s)
    assert "https://i.imgur.com/abc.png#4827766048" in iocs["urls"]
    assert "https://i.imgur.com/def.png#4827766048" in iocs["urls"]
    assert len(iocs["urls"]) == 2

    s = """<IMg SRc="https://i.imgur.com/abc.png"/><br>"""
    iocs = find_iocs(s)
    assert iocs["urls"] == ["https://i.imgur.com/abc.png"]

    s = """(https://i.imgur.com/abc.png)"""
    iocs = find_iocs(s)
    assert iocs["urls"] == ["https://i.imgur.com/abc.png"]

    s = """(https://i.imgur.com/abc.png#abc)"""
    iocs = find_iocs(s)
    assert iocs["urls"] == ["https://i.imgur.com/abc.png#abc"]

    s = """[https://i.imgur.com/abc.png](https://i.imgur.com/abc.png)"""
    iocs = find_iocs(s)
    assert iocs["urls"] == ["https://i.imgur.com/abc.png"]

    s = """[https://i.imgur.com/abc.png#abc](https://i.imgur.com/abc.png#abc)"""
    iocs = find_iocs(s)
    assert iocs["urls"] == ["https://i.imgur.com/abc.png#abc"]


def test_domain_parsing():
    s = "Host: dfasdfa (mz-fcb301p.ocn.ad.jp asdfsdafs"
    iocs = find_iocs(s)
    assert iocs["domains"] == ["mz-fcb301p.ocn.ad.jp"]

    s = "smtp.mailfrom"
    iocs = find_iocs(s)
    assert iocs["domains"] == []

    s = "bar.com"
    iocs = find_iocs(s)
    assert iocs["domains"] == ["bar.com"]

    s = 'bar.com"'
    iocs = find_iocs(s)
    assert iocs["domains"] == ["bar.com"]

    s = "bar.com'"
    iocs = find_iocs(s)
    assert iocs["domains"] == ["bar.com"]

    s = "bar.com."
    iocs = find_iocs(s)
    assert iocs["domains"] == ["bar.com"]

    # make sure domains of different casings are properly parsed: https://github.com/fhightower/ioc-finder/issues/47
    iocs = find_iocs("BAR.com")
    assert iocs["domains"] == ["bar.com"]
    iocs = find_iocs("bar.COM")
    assert iocs["domains"] == ["bar.com"]
    iocs = find_iocs("BAR.COM")
    assert iocs["domains"] == ["bar.com"]


def test_email_address_parsing():
    s = 'my email is: foo"bar@gmail.com'
    iocs = find_iocs(s)
    assert iocs["email_addresses_complete"] == ['foo"bar@gmail.com']
    assert iocs["email_addresses"] == ["bar@gmail.com"]

    s = "Abc\\@def@example.com"
    iocs = find_iocs(s)
    print(iocs["email_addresses_complete"])
    print(iocs["email_addresses"])
    assert iocs["email_addresses_complete"] == ["Abc\\@def@example.com"]
    assert iocs["email_addresses"] == ["def@example.com"]

    s = 'foobar@gmail.com"'
    iocs = find_iocs(s)
    assert iocs["email_addresses_complete"] == ["foobar@gmail.com"]
    assert iocs["email_addresses"] == ["foobar@gmail.com"]

    s = "foobar@gmail.comahhhhhhhh"
    iocs = find_iocs(s)
    assert iocs["email_addresses_complete"] == []
    assert iocs["email_addresses"] == []

    s = '"foobar@gmail.com'
    iocs = find_iocs(s)
    assert iocs["email_addresses_complete"] == ['"foobar@gmail.com']
    assert iocs["email_addresses"] == ["foobar@gmail.com"]

    s = "smtp.mailfrom=example@example.com"
    iocs = find_iocs(s)
    assert iocs["email_addresses_complete"] == ["smtp.mailfrom=example@example.com"]
    assert iocs["email_addresses"] == ["example@example.com"]

    s = '"foo@bar.com"'
    iocs = find_iocs(s)
    assert iocs["email_addresses_complete"] == ['"foo@bar.com']
    assert iocs["email_addresses"] == ["foo@bar.com"]

    # making sure that the `parse_domain_from_email_address` argument is working properly
    s = "foo@bar.com."
    iocs = find_iocs(s, parse_domain_from_email_address=False)
    assert iocs["email_addresses"] == ["foo@bar.com"]
    assert iocs["domains"] == []

    s = '"foo@bar.com'
    iocs = find_iocs(s)
    assert iocs["email_addresses"] == ["foo@bar.com"]

    # validating https://github.com/fhightower/ioc-finder/issues/40 is fixed
    s = "-----foo@bar.com"
    iocs = find_iocs(s)
    assert iocs["email_addresses"] == ["foo@bar.com"]

    s = "foo-burt@bar.com f-1@bar.com"
    iocs = find_iocs(s)
    assert len(iocs["email_addresses"]) == 2
    assert "foo-burt@bar.com" in iocs["email_addresses"]
    assert "f-1@bar.com" in iocs["email_addresses"]


def test_erroneous_ip_address_parsing():
    # the two tests below make sure that IP addresses are not parsed from strings with decimals in them
    s = "2018.12.15.14.05.43"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []

    s = "111.12.15.14.05.43"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []

    s = ".18.12.15.14"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []

    s = "18.12.15.1411111111"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []

    s = "018.12.15.14"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == ["18.12.15.14"]

    s = "18.12.15.14."
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == ["18.12.15.14"]

    # the three tests below make sure that IP addresses are not parsed from sequences with large numbers in them
    s = "1112.15.14.05"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []

    s = "15.1112.14.05"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []

    s = "15.14.05.1112"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []


def test_ip_address_systematically():
    # TODO: for many of the assertions below, I would like to be more explicit; I would like to change tests like `len(iocs['ipv4s']) == 1` to `iocs['ipv4s'] == ['1.1.1.1']`
    s = "1.1.1.1"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == ["1.1.1.1"]

    s = ".1.1.1.1"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []

    # I would like to match in this situation to capture ip address that are at the end of a sentence
    s = "1.1.1.1."
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == ["1.1.1.1"]

    s = ".1.1.1.1."
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []

    s = "1.1.1.1.1"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []

    s = ".1.1.1.1.1"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []

    s = "1.1.1.1.1."
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []

    s = ".1.1.1.1.1."
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []

    s = "1.1.1.1.1.1"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []

    s = "1.1.1.1.a"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []

    s = "1.01.1.1"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == ["1.1.1.1"]

    s = "01.1.1.1"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == ["1.1.1.1"]

    s = "01.01.1.1"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == ["1.1.1.1"]

    s = "0001.1.1.1"
    iocs = find_iocs(s)
    assert iocs["ipv4s"] == []


def test_onion_parsing():
    s = "foo.onion"
    iocs = find_iocs(s)
    assert iocs["domains"] == ["foo.onion"]

    s = "http://foo.onion/test"
    iocs = find_iocs(s)
    assert iocs["urls"] == ["http://foo.onion/test"]
    assert iocs["domains"] == ["foo.onion"]


def test_deduplication_of_indicators_with_different_cases():
    s = "example.com Example.com exAmplE.com"
    iocs = find_iocs(s)
    assert iocs["domains"] == ["example.com"]

    s = "bad@example.com bad@Example.com bad@exAmplE.com"
    iocs = find_iocs(s)
    assert iocs["email_addresses"] == ["bad@example.com"]

    s = "bad@example.com Bad@example.com"
    iocs = find_iocs(s)
    assert iocs["email_addresses"] == ["bad@example.com"]

    s = "http://example.com/test http://EXAMple.com/test"
    iocs = find_iocs(s)
    assert iocs["urls"] == ["http://example.com/test"]

    s = "http://example.com/test http://EXAMple.com/TEST"
    iocs = find_iocs(s)
    assert len(iocs["urls"]) == 2
    assert "http://example.com/test" in iocs["urls"]
    assert "http://example.com/TEST" in iocs["urls"]


def test_google_adsense_publisher_ids():
    s = "PUB-1234567891234567"
    iocs = find_iocs(s)
    assert iocs["google_adsense_publisher_ids"] == ["pub-1234567891234567"]

    s = "pUb-1234567891234567"
    iocs = find_iocs(s)
    assert iocs["google_adsense_publisher_ids"] == []

    s = "PUB-1234567891234567"
    iocs = find_iocs(s)
    assert iocs["google_adsense_publisher_ids"] == ["pub-1234567891234567"]


def test_google_analyitics_tracker_ids():
    s = "ua-000000-1"
    iocs = find_iocs(s)
    assert iocs["google_analytics_tracker_ids"] == ["UA-000000-1"]

    s = "uA-000000-1"
    iocs = find_iocs(s)
    assert iocs["google_analytics_tracker_ids"] == []

    s = "UA-000000-1"
    iocs = find_iocs(s)
    assert iocs["google_analytics_tracker_ids"] == ["UA-000000-1"]


def test_google_casing_deduplication():
    s = "pub-1234567891234567 PUB-1234567891234567 pUb-1234567891234567"
    iocs = find_iocs(s)
    assert iocs["google_adsense_publisher_ids"] == ["pub-1234567891234567"]

    s = "UA-000000-1 ua-000000-1"
    iocs = find_iocs(s)
    assert iocs["google_analytics_tracker_ids"] == ["UA-000000-1"]


def test_not_parsing_imphash():
    s = "imphash 18ddf28a71089acdbab5038f58044c0a"
    iocs = find_iocs(s, parse_imphashes=False)
    assert "imphashes" not in iocs
    # even if we aren't parsing imphashes, they will still be removed and, thus, not parsed as md5s
    assert iocs["md5s"] == []


def test_not_parsing_authentihash():
    s = "authentihash 3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4"
    iocs = find_iocs(s, parse_authentihashes=False)
    assert "authentihashes" not in iocs
    # even if we aren't parsing authentihashes, they will still be removed and, thus, not parsed as sha256s
    assert iocs["sha256s"] == []


def test_mac_address_parsing():
    s = "2019.02.15"
    iocs = find_iocs(s)
    assert iocs["mac_addresses"] == []


def test_unix_file_paths__not_detect_url():
    # https://github.com/fhightower/ioc-finder/issues/42
    s = "https://twitter.com/"
    iocs = find_iocs(s)
    assert iocs["file_paths"] == []


def test_ipv6_parsing():
    # https://github.com/fhightower/ioc-finder/issues/37
    s = "11:04:10 -0500"
    iocs = find_iocs(s)
    assert iocs["ipv6s"] == []


def test_ssdeep_parsing():
    # https://github.com/fhightower/ioc-finder/issues/36
    s = "11:04:10 -0500"
    iocs = find_iocs(s)
    assert iocs["ssdeeps"] == []


def test_certificate_serial_number_issue_96():
    # see https://github.com/fhightower/ioc-finder/issues/96
    s = """SolarWinds.Orion.Core.BusinessLayer.dll is signed by SolarWinds, using the certificate with serial number 0f:e9:73:75:20:22:a6:06:ad:f2:a3:6e:34:5d:c0:ed. The file was signed on March 24, 2020."""
    observables = find_iocs(s)
    print(observables)
    assert observables["ipv6s"] == []
    assert observables["mac_addresses"] == []
