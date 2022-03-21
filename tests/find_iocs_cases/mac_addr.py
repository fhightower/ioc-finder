from pytest import param

MAC_DATA = [
    param(
        "AA-F2-C9-A6-B3-4F AB:F2:C9:A6:B3:4F ACF2.C9A6.B34F",
        {"mac_addresses": ["AA-F2-C9-A6-B3-4F", "AB:F2:C9:A6:B3:4F", "ACF2.C9A6.B34F"]},
        {},
        id="mac_1",
    ),
    param(
        "aa-f2-c9-a6-b3-4f ab:f2:c9:a6:b3:4f acf2.c9a6.b34f",
        {"mac_addresses": ["aa-f2-c9-a6-b3-4f", "ab:f2:c9:a6:b3:4f", "acf2.c9a6.b34f"]},
        {},
        id="mac_2",
    ),
]
