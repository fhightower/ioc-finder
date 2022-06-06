from pytest import param

ASN_DATA = [
    param("as1234", {"asns": ["ASN1234"]}, {}, id="asn_1"),
    param("asn1234", {"asns": ["ASN1234"]}, {}, id="asn_2"),
    param("asn 1234", {"asns": ["ASN1234"]}, {}, id="asn_3"),
    param("AS1234", {"asns": ["ASN1234"]}, {}, id="asn_4"),
    param("AS 1234", {"asns": ["ASN1234"]}, {}, id="asn_5"),
    param("ASN 1234", {"asns": ["ASN1234"]}, {}, id="asn_6"),
    param('here is an asn: "AS1234', {"asns": ["ASN1234"]}, {}, id="asn_7"),
    param("NWD2HUBCAS1234.ad.analog.com", {"domains": ["nwd2hubcas1234.ad.analog.com"]}, {}, id="asn_8"),
    param("here is an asn: AS1234foobar", {}, {}, id="asn_9"),
    param("as1234", {"asns": ["ASN1234"]}, {}, id="asn_10"),
    param("just as 2014", {}, {}, id="asn_11"),
]
