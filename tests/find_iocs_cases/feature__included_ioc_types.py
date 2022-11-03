"""These tests make sure the included_ioc_types parameter is working properly.

Each test below passes a string with two IOC types into the find_iocs function, but only specifies one `included_ioc_types` argument to ensure it is handled properly."""

from pytest import param

from ioc_finder.ioc_finder import DEFAULT_IOC_TYPES

IOC_EXAMPLES = {
    "domains": ["abc.py", "bar.com", "example.com", "foo.com", "swissjabber.de"],
    "urls": ["https://example.com/test%20page/foo.com/bingo.php?q=bar.com"],
    "xmpp_addresses": ["foo@swissjabber.de"],
    "email_addresses_complete": ["me@example.com"],
    "email_addresses": ["me@example.com"],
    "ipv4_cidrs": ["1.1.1.1/0"],
    "imphashes": ["18ddf28a71089acdbab5038f58044c0a"],
    "authentihashes": ["3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4"],
    "ipv4s": ["1.1.1.1"],
    "ipv6s": ["2001:0db8:0000:0000:0000:ff00:0042:8329"],
    "sha512s": ["a" * 128],
    "sha256s": ["a" * 64],
    "sha1s": ["a" * 40],
    "md5s": ["a" * 32],
    "ssdeeps": [
        "12288:QYV6MorX7qzuC3QHO9FQVHPF51jgcSj2EtPo/V7I6R+Lqaw8i6hG0:vBXu9HGaVHh4Po/VU6RkqaQ6F",
        "0000:0000:ff00",
        "2001:0db8:0000",
    ],  # I don't like that the components of an ipv6 can be parsed as an ssdeep... I've ticketed this here: https://github.com/fhightower/ioc-finder/issues/228
    "asns": ["ASN123"],
    "cves": ["CVE-2022-1234"],
    "registry_key_paths": [r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows"],
    "google_adsense_publisher_ids": ["pub-1234567891234567"],
    "google_analytics_tracker_ids": ["UA-000000-1"],
    "bitcoin_addresses": ["18ddf28a71089acdbab5038f58044c0a", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"],
    "monero_addresses": [
        "496aKKdqF1xQSSEzw7wNrkZkDUsCD5cSmNCfVhVgEps52WERBcLDGzdF5UugmFoHMm9xRJdewvK2TFfAJNwEV25rTcVF5Vp"
    ],
    "mac_addresses": ["AA-F2-C9-A6-B3-4F"],
    "user_agents": [
        "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; InfoPath.1) TLP"
    ],  # I don't like this parsing... I've ticketed this for improvement here: https://github.com/fhightower/ioc-finder/issues/227
    "tlp_labels": ["TLP:RED"],
    "mac_addresses": ["AA-F2-C9-A6-B3-4F"],
    "file_paths": ["~/foo/bar/abc.py"],
    "attack_mitigations": {"enterprise": ["M1036", "M1015"]},
    "attack_tactics": {"pre_attack": ["TA0012"]},
    "attack_techniques": {"pre_attack": ["T1329"]},
}
all_ioc_text = " ".join([val for sublist in IOC_EXAMPLES.values() for val in sublist])

# this is a hack to be fixed in https://github.com/fhightower/ioc-finder/issues/224
# imphashes and authentihashes require the hash to be prefixed with `imphash` and `authentihash` respectively, but when parsed, only the hash itself will be present
all_ioc_text = all_ioc_text.replace(IOC_EXAMPLES["imphashes"][0], f'imphash {IOC_EXAMPLES["imphashes"][0]}')  # type: ignore
all_ioc_text = all_ioc_text.replace(
    IOC_EXAMPLES["authentihashes"][0], f'authentihash {IOC_EXAMPLES["authentihashes"][0]}'  # type: ignore
)
all_ioc_text = all_ioc_text.replace(IOC_EXAMPLES["user_agents"][0], IOC_EXAMPLES["user_agents"][0].rstrip(" TLP"))  # type: ignore
# add the attack data
all_ioc_text = all_ioc_text + " " + " ".join(IOC_EXAMPLES["attack_mitigations"]["enterprise"])  # type: ignore
all_ioc_text = all_ioc_text + " " + " ".join(IOC_EXAMPLES["attack_tactics"]["pre_attack"])  # type: ignore
all_ioc_text = all_ioc_text + " " + " ".join(IOC_EXAMPLES["attack_techniques"]["pre_attack"])  # type: ignore


individual_included_ioc_types_tests = []

for type_ in DEFAULT_IOC_TYPES:
    individual_included_ioc_types_tests.append(
        param(
            all_ioc_text,
            {type_: IOC_EXAMPLES[type_]},
            {"included_ioc_types": [type_]},
            id=f"Only find {type_} with included_ioc_types",
        )
    )


multiple_included_ioc_types_tests = []

# make sure multiple included_ioc_types are handled properly
multiple_included_ioc_types_tests.append(
    param(
        "https://example.com/test%20page/foo.com/bingo.php?q=bar.com",
        {
            "domains": ["bar.com", "example.com", "foo.com"],
            "urls": ["https://example.com/test%20page/foo.com/bingo.php?q=bar.com"],
        },
        {"included_ioc_types": ["domains", "urls"]},
        id="Find multiple data types",
    )
)

# make sure multiple included_ioc_types work well with other kwargs - the list of domains is missing `foo.com` b/c `parse_from_url_path` is False
multiple_included_ioc_types_tests.append(
    param(
        "https://example.com/test%20page/foo.com/bingo.php?q=bar.com",
        {
            "domains": ["bar.com", "example.com"],
            "urls": ["https://example.com/test%20page/foo.com/bingo.php?q=bar.com"],
        },
        {"included_ioc_types": ["domains", "urls"], "parse_from_url_path": False},
        id="Find multiple data types",
    )
)
