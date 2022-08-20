from pytest import param

URL_DATA = [
    param(
        "https://example.com/test%20page/foo.com/bingo.php?q=bar.com",
        {
            "urls": ["https://example.com/test%20page/foo.com/bingo.php?q=bar.com"],
            "domains": ["bar.com", "foo.com", "example.com"],
        },
        {},
        id="URL and domains parsed",
    ),
    param(
        "Foo https://citizenlab.ca/about/), bar",
        {
            "urls": ["https://citizenlab.ca/about/"],
        },
        {"parse_domain_from_url": False},
        id="URL boundary w/ ) handled properly",
    ),
    param(
        "DownloadString('https://example[.]com/rdp.ps1');g $I DownloadString(\"https://example[.]com/rdp.ps2\");g $I",
        {
            "urls": ["https://example.com/rdp.ps1", "https://example.com/rdp.ps2"],
        },
        {"parse_domain_from_url": False},
        id="URL boundary w/ single or double quotes handled properly",
    ),
    param(
        "https://example.com/g//foo",
        {
            "urls": ["https://example.com/g//foo"],
        },
        {"parse_domain_from_url": False},
        id="Consecutive slashes handled properly",
    ),
]
