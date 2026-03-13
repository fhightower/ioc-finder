from pytest import param

URL_DATA = [
    param(
        "https://example.com/test%20page/foo.com/bingo.php?q=bar.com",
        {
            "urls": ["https://example.com/test%20page/foo.com/bingo.php?q=bar.com"],
            "urls_complete": ["https://example.com/test%20page/foo.com/bingo.php?q=bar.com"],
            "domains": ["bar.com", "foo.com", "example.com"],
        },
        {},
        id="URL and domains parsed",
    ),
    param(
        "Foo https://citizenlab.ca/about/), bar",
        {
            "urls": ["https://citizenlab.ca/about/"],
            "urls_complete": ["https://citizenlab.ca/about/"],
        },
        {"parse_domain_from_url": False},
        id="URL boundary w/ ) handled properly",
    ),
    param(
        "DownloadString('https://example[.]com/rdp.ps1');g $I DownloadString(\"https://example[.]com/rdp.ps2\");g $I",
        {
            "urls": ["https://example.com/rdp.ps1", "https://example.com/rdp.ps2"],
            "urls_complete": ["https://example.com/rdp.ps1", "https://example.com/rdp.ps2"],
        },
        {"parse_domain_from_url": False},
        id="URL boundary w/ single or double quotes handled properly",
    ),
    param(
        "https://example.com/g//foo",
        {
            "urls": ["https://example.com/g//foo"],
            "urls_complete": ["https://example.com/g//foo"],
        },
        {"parse_domain_from_url": False},
        id="Consecutive slashes handled properly",
    ),
    param(
        "https://example.com/abc,False,False",
        {
            "urls": ["https://example.com/abc"],
            "urls_complete": ["https://example.com/abc,False,False"],
            "domains": ["example.com"],
        },
        {},
        id="Complete URLs parsed when urls are not",
    ),
    param(
        "example.com/abc,False,False",
        {
            "urls": ["example.com/abc"],
            "urls_complete": ["example.com/abc,False,False"],
            "domains": ["example.com"],
        },
        {},
        id="Complete scheme-less URLs parsed when urls are not",
    ),
    param(
        "example.com/abc,False,False foo.com",
        {
            "urls": ["example.com/abc"],
            "urls_complete": ["example.com/abc,False,False"],
            "domains": ["foo.com"],
        },
        {"parse_domain_from_url": False},
        id="Complete scheme-less URLs support domain removal",
    ),
    param(
        "http://userid:password@example.com:8080/",
        {
            "urls": ["password@example.com:8080/"],
            "urls_complete": ["http://userid:password@example.com:8080/"],
            "domains": ["example.com"],
        },
        {},
        id="Complete URLs support userinfo in authority",
    ),
]
