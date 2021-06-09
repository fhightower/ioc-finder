import pytest

from ioc_finder import find_iocs


@pytest.mark.parametrize(
    "text",
    [
        ('as1234',),
        ('asn1234',),
        # ('as 1234',),  # this is no longer matched - see https://github.com/fhightower/ioc-finder/issues/136
        ('asn 1234',),
        ('AS1234',),
        ('ASN1234',),
        ('AS 1234',),
        ('ASN 1234',),
    ],
)
def test_asn_parsing__systematic(text):
    """Make sure ASNS are found and standardized."""
    assert find_iocs(text[0])['asns'] == ['ASN1234']


@pytest.mark.parametrize(
    "text,expected_asns",
    [
        ('NWD2HUBCAS1234.ad.analog.com', []),
        ('here is an asn: "AS1234"', ['ASN1234']),
        ('here is an asn: AS1234foobar', []),
        ('as1234', ['ASN1234']),
        ('just as 2014', []),  # tests https://github.com/fhightower/ioc-finder/issues/136
    ],
)
def test_asn_parsing__edge_cases(text, expected_asns):
    assert find_iocs(text)['asns'] == expected_asns
