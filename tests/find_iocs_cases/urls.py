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
]
