from ioc_finder import find_iocs


def test_tlp_labels():
    s = "tlp amber and TLP:RED"
    iocs = find_iocs(s)
    assert len(iocs["tlp_labels"]) == 2
    assert "TLP:RED" in iocs["tlp_labels"]
    assert "TLP:AMBER" in iocs["tlp_labels"]

    s = "tlp-Amber and TLPRED TlpGreen"
    iocs = find_iocs(s)
    assert len(iocs["tlp_labels"]) == 3
    assert "TLP:RED" in iocs["tlp_labels"]
    assert "TLP:AMBER" in iocs["tlp_labels"]
    assert "TLP:GREEN" in iocs["tlp_labels"]


def test_domain_parsing():
    s = "this is just a (google.com) test of example.com"
    iocs = find_iocs(s)
    assert len(iocs["domains"]) == 2
    assert "google.com" in iocs["domains"]


def test_ipv4_parsing():
    s = "this is just a (1.2.3.54) test of 255.255.1.255 255.256.344.1"
    iocs = find_iocs(s)
    assert len(iocs["ipv4s"]) == 2
    assert "1.2.3.54" in iocs["ipv4s"]
    assert "255.255.1.255" in iocs["ipv4s"]
    assert "255.256.344.1" not in iocs["ipv4s"]


def test_ipv6_parsing():
    s = "2001:0db8:0000:0000:0000:ff00:0042:8329 testing 2001:db8:0:0:0:ff00:42:8329 shfaldkafsdfa 2001:db8::ff00:42:8329 asdfadfas afkj;fl ::1 kljfkadf 1:1"
    iocs = find_iocs(s)
    assert len(iocs["ipv6s"]) == 4
    # TODO: the following 3 ipv6s addresses are the same representation of the same thing; I need to deduplicate these more thoroughly in the parsing function
    assert "2001:0db8:0000:0000:0000:ff00:0042:8329" in iocs["ipv6s"]
    assert "2001:db8:0:0:0:ff00:42:8329" in iocs["ipv6s"]
    assert "2001:db8::ff00:42:8329" in iocs["ipv6s"]
    assert "::1" in iocs["ipv6s"]
    assert "1:1" not in iocs["ipv6s"]


def test_email_address_parsing():
    s = "test@a.com bingo@en.wikipedia.com foo@a.com'.format('a'*63 bar@b.a.com'.format('a'*63, 'a'*63 bad@test-ing.com me@2600.com john.smith(comment)@example.com (comment)john.smith@example.com \"John..Doe\"@example.com' test@[192.168.0.1]"

    iocs = find_iocs(s)["email_addresses_complete"]
    print(iocs)
    assert len(iocs) == 10
    assert "test@a.com" in iocs
    assert "bingo@en.wikipedia.com" in iocs
    assert "foo@a.com" in iocs
    assert "bar@b.a.com" in iocs
    assert "bad@test-ing.com" in iocs
    assert "me@2600.com" in iocs
    assert "john.smith(comment)@example.com" in iocs
    assert "(comment)john.smith@example.com" in iocs
    assert '"John..Doe"@example.com' in iocs
    assert "test@[192.168.0.1]" in iocs

    iocs = find_iocs("a@example.com")
    assert iocs["email_addresses_complete"][0] == "a@example.com"


def test_complex_email_address_parsing():
    s = "john.smith(comment)@example.com"
    iocs = find_iocs(s)
    assert "john.smith(comment)@example.com" in iocs["email_addresses_complete"]


def test_simple_email_address_parsing():
    s = "test@a.com bingo@en.wikipedia.com foo@a.com'.format('a'*63 bar@b.a.com'.format('a'*63, 'a'*63 bad@test-ing.com me@2600.com john.smith(comment)@example.com (comment)john.smith@example.com \"John..Doe\"@example.com' test@[192.168.0.1]"

    iocs = find_iocs(s)
    assert len(iocs["email_addresses"]) == 8
    assert "test@a.com" in iocs["email_addresses"]
    assert "bingo@en.wikipedia.com" in iocs["email_addresses"]
    assert "foo@a.com" in iocs["email_addresses"]
    assert "bar@b.a.com" in iocs["email_addresses"]
    assert "bad@test-ing.com" in iocs["email_addresses"]
    assert "me@2600.com" in iocs["email_addresses"]
    assert "john.smith@example.com" in iocs["email_addresses"]
    assert "test@[192.168.0.1]" in iocs["email_addresses"]

    iocs = find_iocs("a@example.com")
    assert iocs["email_addresses"][0] == "a@example.com"


def test_url_parsing():
    invalid_urls = [
        "foo@{}.com".format("a" * 64),
        "!@.com",
        "foo@abc",
        "@@@@-hi-.com",
        "@_hi_.com",
        "me@*hi*.com",
        "foo{}.com".format("a" * 64),
        ".com",
        "abc",
        "-hi-.com",
        "_hi_.com",
        "*hi*.com",
    ]

    valid_urls = [
        "https://a.com",
        "https://en.wikipedia.com",
        "https://{}.com".format("a" * 63),
        "https://{}.{}.com".format("a" * 63, "a" * 63),
        "https://test-ing.com",
        "https://2600.com",
        "https://example.com",
        "http://example.com",
        "ftp://example.com",
    ]

    iocs = find_iocs(" ".join(valid_urls))
    assert len(iocs["urls"]) == 9
    # make sure domains are being parsed from the valid urls as well
    assert len(iocs["domains"]) == 7

    iocs = find_iocs(" ".join(invalid_urls))
    assert len(iocs["urls"]) == 0

    s = "http://8pretgdl.r.us-east-1.awstrack.me/L0/http:%2F%2Fwww.excelgoodies.com%2Fexcel-vba-training-in-virginia%23course-content/1/0100016ed23f4bef-b14931bd-26f6-4130-9c37-c4f9902a771d-000000/mHJBuJ8D1RcIDE3jrWkdw4I9im4=138"
    iocs = find_iocs(s)
    print(iocs["urls"])
    assert iocs["urls"] == [
        "http://8pretgdl.r.us-east-1.awstrack.me/L0/http:%2F%2Fwww.excelgoodies.com%2Fexcel-vba-training-in-virginia%23course-content/1/0100016ed23f4bef-b14931bd-26f6-4130-9c37-c4f9902a771d-000000/mHJBuJ8D1RcIDE3jrWkdw4I9im4=138"
    ]

    s = "https://www.virustotal.com/gui/file/2f3ec0e4998909bb0efab13c82d30708ca9f88679e42b75ef13ea0466951d862/detection"
    iocs = find_iocs(s)
    assert iocs["sha256s"] == ["2f3ec0e4998909bb0efab13c82d30708ca9f88679e42b75ef13ea0466951d862"]

    # this was implemented for https://github.com/fhightower/ioc-finder/issues/87
    s = "https://www.virustotal.com/gui/file/2f3ec0e4998909bb0efab13c82d30708ca9f88679e42b75ef13ea0466951d862/detection"
    iocs = find_iocs(s, parse_from_url_path=False)
    assert iocs["sha256s"] == []

    # this was implemented for https://github.com/fhightower/ioc-finder/issues/87
    s = "https://www.virustotal.com/gui/file/2f3ec0e4998909bb0efab13c82d30708ca9f88679e42b75ef13ea0466951d862/detection"
    iocs = find_iocs(s, parse_from_url_path=False, parse_urls_without_scheme=False)
    assert iocs["urls"] == [
        "https://www.virustotal.com/gui/file/2f3ec0e4998909bb0efab13c82d30708ca9f88679e42b75ef13ea0466951d862/detection"
    ]
    assert iocs["sha256s"] == []


def test_file_hash_parsing():
    s = "{} {} {} {} {}".format("A" * 32, "a" * 32, "b" * 40, "c" * 64, "d" * 128)
    iocs = find_iocs(s)
    assert len(iocs["md5s"]) == 1
    assert len(iocs["sha1s"]) == 1
    assert len(iocs["sha256s"]) == 1
    assert len(iocs["sha512s"]) == 1


def test_cve_parsing():
    s = "cve-2014-1000 cve 2014-1001 cve-1999-1002 CVE 2999-1003 CVE 1928-1004"
    iocs = find_iocs(s)
    assert len(iocs["cves"]) == 5
    assert "CVE-2014-1000" in iocs["cves"]
    assert "CVE-2014-1001" in iocs["cves"]
    assert "CVE-1999-1002" in iocs["cves"]
    assert "CVE-2999-1003" in iocs["cves"]
    assert "CVE-1928-1004" in iocs["cves"]


def test_ipv4_cidr_parsing():
    s = "1.2.3.4/0 1.2.3.4/10 1.2.3.4/20 1.2.3.4/32"
    iocs = find_iocs(s)
    assert len(iocs["ipv4_cidrs"]) == 4
    assert "1.2.3.4/0" in iocs["ipv4_cidrs"]
    assert "1.2.3.4/10" in iocs["ipv4_cidrs"]
    assert "1.2.3.4/20" in iocs["ipv4_cidrs"]
    assert "1.2.3.4/32" in iocs["ipv4_cidrs"]

    s = "1.2.3.4/0 1.2.3.4/10 1.2.3.4/20 1.2.3.4/32"
    iocs = find_iocs(s, parse_address_from_cidr=False)
    assert len(iocs["ipv4_cidrs"]) == 4
    assert len(iocs["ipv4s"]) == 0


def test_registry_key_parsing():
    s = r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows HKLM\Software\Microsoft\Windows HKCC\Software\Microsoft\Windows"
    iocs = find_iocs(s)
    assert sorted(
        [
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows",
            r"HKLM\Software\Microsoft\Windows",
            r"HKCC\Software\Microsoft\Windows",
        ]
    ) == sorted(iocs["registry_key_paths"])


def test_adsense_publisher_id_parsing():
    s = "pub-1234567891234567"
    iocs = find_iocs(s)
    assert len(iocs["google_adsense_publisher_ids"]) == 1
    iocs["google_adsense_publisher_ids"][0] == "pub-1234567891234567"

    s = "pub-1234567891234567 pub-9383614236930773"
    iocs = find_iocs(s)
    assert len(iocs["google_adsense_publisher_ids"]) == 2
    assert "pub-1234567891234567" in iocs["google_adsense_publisher_ids"]
    assert "pub-9383614236930773" in iocs["google_adsense_publisher_ids"]


def test_analytics_publisher_id_parsing():
    s = "UA-000000-2"
    iocs = find_iocs(s)
    assert len(iocs["google_analytics_tracker_ids"]) == 1
    assert iocs["google_analytics_tracker_ids"][0] == "UA-000000-2"

    s = "UA-000000-2 UA-00000000-99"
    iocs = find_iocs(s)
    assert len(iocs["google_analytics_tracker_ids"]) == 2
    assert "UA-000000-2" in iocs["google_analytics_tracker_ids"]
    assert "UA-00000000-99" in iocs["google_analytics_tracker_ids"]


def test_bitcoin_parsing():
    s = """1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.
P2SH type starting with the number 3, eg: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy.
Bech32 type starting with bc1, eg: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"""
    iocs = find_iocs(s)
    assert len(iocs["bitcoin_addresses"]) == 3
    assert "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" in iocs["bitcoin_addresses"]
    assert "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy" in iocs["bitcoin_addresses"]
    assert "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in iocs["bitcoin_addresses"]


def test_xmpp_address_parsing():
    s = """foo@swissjabber.de bar@jabber.zone bom@jabber.sow.as me@example.com"""
    iocs = find_iocs(s)
    assert len(iocs["xmpp_addresses"]) == 3
    assert "foo@swissjabber.de" in iocs["xmpp_addresses"]
    assert "bar@jabber.zone" in iocs["xmpp_addresses"]
    assert "bom@jabber.sow.as" in iocs["xmpp_addresses"]
    assert len(iocs["domains"]) == 4
    # make sure the xmpp addresses are not also parsed as email addresses
    assert len(iocs["email_addresses"]) == 1

    iocs = find_iocs(s, parse_domain_name_from_xmpp_address=False)
    assert len(iocs["xmpp_addresses"]) == 3
    assert "foo@swissjabber.de" in iocs["xmpp_addresses"]
    assert "bar@jabber.zone" in iocs["xmpp_addresses"]
    assert "bom@jabber.sow.as" in iocs["xmpp_addresses"]
    assert len(iocs["domains"]) == 1
    # make sure the xmpp addresses are not also parsed as email addresses
    assert len(iocs["email_addresses"]) == 1


def test_mac_address_parsing():
    s = "AA-F2-C9-A6-B3-4F AB:F2:C9:A6:B3:4F ACF2.C9A6.B34F"

    iocs = find_iocs(s)
    assert len(iocs["mac_addresses"]) == 3
    assert "AA-F2-C9-A6-B3-4F" in iocs["mac_addresses"]
    assert "AB:F2:C9:A6:B3:4F" in iocs["mac_addresses"]
    assert "ACF2.C9A6.B34F" in iocs["mac_addresses"]

    # same thing, just lower-case
    s = "aa-f2-c9-a6-b3-4f ab:f2:c9:a6:b3:4f acf2.c9a6.b34f"
    iocs = find_iocs(s)
    assert len(iocs["mac_addresses"]) == 3
    assert "aa-f2-c9-a6-b3-4f" in iocs["mac_addresses"]
    assert "ab:f2:c9:a6:b3:4f" in iocs["mac_addresses"]
    assert "acf2.c9a6.b34f" in iocs["mac_addresses"]


def test_ssdeep_parsing():
    s = "1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U"
    iocs = find_iocs(s)
    assert len(iocs["ssdeeps"]) == 1
    assert iocs["ssdeeps"][0] == "1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U"

    s = "ahdfadsfa 1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U,000/000/000000001 adfasf"
    iocs = find_iocs(s)
    assert len(iocs["ssdeeps"]) == 1
    assert iocs["ssdeeps"][0] == "1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U"

    s = """c2b257868686c861d43c6cf3de146b8812778c8283f7d
Threat  Zepakab/Zebrocy Downloader
ssdeep  12288:QYV6MorX7qzuC3QHO9FQVHPF51jgcSj2EtPo/V7I6R+Lqaw8i6hG0:vBXu9HGaVHh4Po/VU6RkqaQ6F"""
    iocs = find_iocs(s)
    assert len(iocs["ssdeeps"]) == 1
    assert iocs["ssdeeps"][0] == "12288:QYV6MorX7qzuC3QHO9FQVHPF51jgcSj2EtPo/V7I6R+Lqaw8i6hG0:vBXu9HGaVHh4Po/VU6RkqaQ6F"

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
    assert len(iocs["ssdeeps"]) == 9
    assert (
        "393216:EW/eKCo9QgoHfHYebwoyC0QStQYEb+G8j3wfVOglnimQyCK+mteYREDWXKF2b:MKg3lbwoyCnCkNHlnimfCSQx8b"
        in iocs["ssdeeps"]
    )
    assert "196608:AGSE26mYSK0iwH8HW9TDl0vnvCZwZEkzzeap7R:Ak28siwH8eRSn25k3eg" in iocs["ssdeeps"]
    assert (
        "98304:O1OCzezOgr4XMP7Af0+Kh7MzplFKuu5XcS9QnCD/VWR6yf4OB6S/mwRTwjf0ih87:k/Y4XMT7YguEXqCD/VWR6yf4Ux/mwR0S"
        in iocs["ssdeeps"]
    )
    assert "96:ukILJhn54RewghSib4xGEHVLFNs+4tihJW6jJenUQrsIvpMMjUg:uk0Jx54usxJHh4gJrJenUQrs2pvIg" in iocs["ssdeeps"]
    assert (
        "196608:rNI4QlKQbWQobu0u3QRBBibfv+Z4Hjy5M+IjunAadLLtt42fAtQSqFhx:rNkK2obu0uBb3K4H28yAGc4RSax" in iocs["ssdeeps"]
    )
    assert (
        "1536:mFbhArcCMbR0S/kjzU6El4mUIR2JPmvY3lpKa38fTXcTns+b3tfZyCLtRs:obNCMbWpU6SzFAPV3lpCjCsQRZyQt6"
        in iocs["ssdeeps"]
    )
    assert (
        "48:CScrEd3jk5BsRSFCWfVsEWABbbpnWSgSX45dc6b5Qla9A+o5R6k7CyNRD5J:XcrEdzHRSFr9sE7XnsDe1CyNRNJ" in iocs["ssdeeps"]
    )
    assert (
        "24:N8Rw5AF4REesFtPP6k216xoWya1oxOKHHwa8peRK8FdigZY5tODrRRK8RfMfde8:N8Rw5AF4+XPyooa2EKnwaGeRJFYpfwzQ"
        in iocs["ssdeeps"]
    )
    assert "1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U" in iocs["ssdeeps"]


def test_imphash_parsing():
    names = ["imphash", "import hash"]
    templates = [
        """SHA-256 093e394933c4545ba7019f511961b9a5ab91156cf791f45de074acad03d1a44a
Dropper {}: 18ddf28a71089acdbab5038f58044c0a
C2 IP: 210.209.127.8:443""",
        "{}: 18ddf28a71089acdbab5038f58044c0a",
        "{} 18ddf28a71089acdbab5038f58044c0a",
        "{}  18ddf28a71089acdbab5038f58044c0a",
        "{}:     18ddf28a71089acdbab5038f58044c0a",
        "{}\t18ddf28a71089acdbab5038f58044c0a",
        "{}\n18ddf28a71089acdbab5038f58044c0a",
        "{} - 18ddf28a71089acdbab5038f58044c0a",
    ]

    for template in templates:
        for name in names:
            print(template)
            iocs = find_iocs(template.format(name))
            assert len(iocs["imphashes"]) == 1
            assert iocs["imphashes"] == ["18ddf28a71089acdbab5038f58044c0a"]
            assert len(iocs["md5s"]) == 0

            iocs = find_iocs(template.format(name.upper()))
            assert len(iocs["imphashes"]) == 1
            assert iocs["imphashes"] == ["18ddf28a71089acdbab5038f58044c0a"]
            assert len(iocs["md5s"]) == 0


def test_authentihash():
    names = ["authentihash"]
    templates = [
        "{} 3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4",
        "{}   3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4",
        "{}: 3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4",
        "{}:     3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4",
        "{} - 3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4",
        "{}-3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4",
        "{}\t3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4",
        "{}\n3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4",
    ]

    for template in templates:
        for name in names:
            print(template)
            iocs = find_iocs(template.format(name))
            assert len(iocs["authentihashes"]) == 1
            assert iocs["authentihashes"] == ["3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4"]
            assert len(iocs["sha256s"]) == 0

            iocs = find_iocs(template.format(name.upper()))
            assert len(iocs["authentihashes"]) == 1
            assert iocs["authentihashes"] == ["3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4"]
            assert len(iocs["sha256s"]) == 0


def test_user_agents():
    s = "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; InfoPath.1)"
    iocs = find_iocs(s)
    assert len(iocs["user_agents"]) == 1
    assert iocs["user_agents"] == ["Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; InfoPath.1)"]

    s = "mozilla/5.0 (windows nt 6.1; wow64) applewebkit/535.11 (khtml, like gecko) chrome/17.0.963.56 safari/535.11 mozilla/5.0 (windows nt 6.1; wow64; rv:11.0) gecko firefox/11.0"
    iocs = find_iocs(s)
    assert len(iocs["user_agents"]) == 2
    assert (
        "mozilla/5.0 (windows nt 6.1; wow64) applewebkit/535.11 (khtml, like gecko) chrome/17.0.963.56 safari/535.11"
        in iocs["user_agents"]
    )
    assert "mozilla/5.0 (windows nt 6.1; wow64; rv:11.0) gecko firefox/11.0" in iocs["user_agents"]

    # test the same thing as above but with different casing to make sure the cases are matched and maintained properly
    s = "Mozilla/5.0 (Windows nt 6.1; wow64) Applewebkit/535.11 (khtml, like Gecko) Chrome/17.0.963.56 Safari/535.11 Mozilla/5.0 (Windows nt 6.1; wow64; rv:11.0) Gecko Firefox/11.0"
    iocs = find_iocs(s)
    assert len(iocs["user_agents"]) == 2
    assert (
        "Mozilla/5.0 (Windows nt 6.1; wow64) Applewebkit/535.11 (khtml, like Gecko) Chrome/17.0.963.56 Safari/535.11"
        in iocs["user_agents"]
    )
    assert "Mozilla/5.0 (Windows nt 6.1; wow64; rv:11.0) Gecko Firefox/11.0" in iocs["user_agents"]


def test_monero_addresses():
    result = find_iocs(
        "496aKKdqF1xQSSEzw7wNrkZkDUsCD5cSmNCfVhVgEps52WERBcLDGzdF5UugmFoHMm9xRJdewvK2TFfAJNwEV25rTcVF5Vp"
    )
    assert result["monero_addresses"] == [
        "496aKKdqF1xQSSEzw7wNrkZkDUsCD5cSmNCfVhVgEps52WERBcLDGzdF5UugmFoHMm9xRJdewvK2TFfAJNwEV25rTcVF5Vp"
    ]

    s = "49Bmp3SfddJRRGNW7GhHyAA2JgcYmZ4EGEix6p3eMNFCd15P2VsK9BHWcZWUNYF3nhf17MoRTRK4j5b7FUMA9zanSn9D3Nk 498s2XeKWYSEhQHGxdMULWdrpaKvSkDsq4855mCuksNL6ez2dk4mMQm8epbr9xvn5LgLPzD5uL9EGeRqWUdEZha1HmZqcyh"
    result = find_iocs(s)
    assert (
        "49Bmp3SfddJRRGNW7GhHyAA2JgcYmZ4EGEix6p3eMNFCd15P2VsK9BHWcZWUNYF3nhf17MoRTRK4j5b7FUMA9zanSn9D3Nk"
        in result["monero_addresses"]
    )
    assert (
        "498s2XeKWYSEhQHGxdMULWdrpaKvSkDsq4855mCuksNL6ez2dk4mMQm8epbr9xvn5LgLPzD5uL9EGeRqWUdEZha1HmZqcyh"
        in result["monero_addresses"]
    )
