from pytest import param

DOMAIN_DATA = [
    param(
        "this is just a (google.com) test of example.com",
        {"domains": ["google.com", "example.com"]},
        id="domain_1"
    )
]
