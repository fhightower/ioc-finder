"""These tests make sure the data_types parameter is working properly.

Each test below passes a string with two IOC types into the find_iocs function, but only specifies one `data_types` argument to ensure it is handled properly."""

from pytest import param
from ioc_finder.ioc_finder import POSSIBLE_DATA_TYPES

IOC_EXAMPLES = {
    'domains': ['foo.com', 'example.com', 'bar.com'],
    'urls': ['https://example.com/test%20page/foo.com/bingo.php?q=bar.com'],
    'xmpp_addresses': ["foo@swissjabber.de"],
    'email_addresses_complete': ['me@example.com'],
    'email_addresses': ['me@example.com'],
    'ipv4_cidrs': ['1.1.1.1/0'],
    'imphashes': ['18ddf28a71089acdbab5038f58044c0a'],
    'authentihashes': ['3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4'],
    'ipv4s': ['1.1.1.1'],
    'ipv6s': ['2001:0db8:0000:0000:0000:ff00:0042:8329'],
    'sha512s': ['a' * 128],
    'sha256s': ['a' * 64],
    'sha1s': ['a' * 40],
    'md5s': ['a' * 32],
    'ssdeeps': ['12288:QYV6MorX7qzuC3QHO9FQVHPF51jgcSj2EtPo/V7I6R+Lqaw8i6hG0:vBXu9HGaVHh4Po/VU6RkqaQ6F'],
    'asns': ['ASN123'],
    'cves': ['CVE1234'],
    'registry_key_paths': ['HKEY_LOCAL_MACHINE\Software\Microsoft\Windows'],
    'google_adsense_publisher_ids': ['pub-1234567891234567'],
    'google_analytics_tracker_ids': ['UA-000000-1'],
    'bitcoin_addresses': ['3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'],
}
ALL_IOC_TEXT = ' '.join([val for sublist in IOC_EXAMPLES.values() for val in sublist])

individual_data_types_tests = []

for type_ in POSSIBLE_DATA_TYPES:
    individual_data_types_tests.append(param(
        ALL_IOC_TEXT ,
        {
            # TODO: CHANGE THIS TO `IOC_EXAMPLES[type_]` ONCE ALL TYPES ARE ADDED TO IOC_EXAMPLES
            type_: IOC_EXAMPLES.get(type_, [])
        },
        {"data_types": [type_]},
        id=f"Only find {type_} with data_types"
    ))


# TODO: ADD EXAMPLES FOR EACH OF THE IOC TYPES BELOW
DATA_TYPES = [
    "monero_addresses",
    "mac_addresses",
    "user_agents",
    "tlp_labels",
    "attack_mitigations",
    "attack_tactics",
    "attack_techniques",
    "file_paths",
    ]
