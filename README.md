# IOC Finder

[![PyPi](https://img.shields.io/pypi/v/ioc_finder.svg)](https://pypi.python.org/pypi/ioc_finder)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/4078c4e3e384431bbe69c35c7f6da7b7)](https://www.codacy.com/app/fhightower/ioc-finder)
[![Build Status](https://travis-ci.org/fhightower/ioc-finder.svg?branch=master)](https://travis-ci.org/fhightower/ioc-finder)
[![codecov](https://codecov.io/gh/fhightower/ioc-finder/branch/master/graph/badge.svg)](https://codecov.io/gh/fhightower/ioc-finder)

Parse [indicators of compromise](https://searchsecurity.techtarget.com/definition/Indicators-of-Compromise-IOC) from text.

## Capabilities

Currently, this package can the following items in a given text:

- IP address (IPv4 and IPv6)
- Email addresses (both standard format (e.g. `test@example.com`) and an email with an IP address as the domain (e.g. `test@[192.168.0.1]`))
- Domain names (support for Unicode domain names (e.g. `ȩxample.com`) is coming soon)
- URLs
- File hashes (md5, sha1, sha256, and sha512)
- Registry Key paths (e.g. `"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows`)
- Autonomous System Numbers (ASNs) (in multiple formats such as `asn1234` and `as 1234`)
- CVEs (e.g. `CVE-2014-1234`)
- CIDR ranges (currently ipv4 ranges; ipv6 ranges coming soon)
- Google Adsense Publisher IDs
- Google Analytics Tracker IDs
- Bitcoin addresses (P2PKH, P2SH, and Bech32)
- Others... if you have any requests, [let me know](https://github.com/fhightower/ioc-finder) (or you can contact me [here](https://hightower.space/contact/) to make private suggestions)!

Also provides some helpful features like:

- Ability to remove an indicator type after it is parsed - For example, if you would like to parse all URLs, but do not want to parse the domain name from each URL, you specify this.

## Installation

To install this package:

```
pip install ioc-finder
```

## Usage

To use this package:

```python
from ioc_finder import find_iocs
text = "This is just an example.com https://example.org/test/bingo.php"
iocs = find_iocs(text)
print('Domains: {}'.format(iocs['domains']))
print('URLs: {}'.format(iocs['urls']))
```

See [test_ioc_finder.py](https://github.com/fhightower/ioc-finder/blob/master/tests/test_ioc_finder.py) for more examples.

## Credits

This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and Floyd Hightower's [python-project-template](https://gitlab.com/fhightower-templates/python-project-template) project template.

Previous iterations of this package were inspired by [https://github.com/mosesschwartz/extract_iocs](https://github.com/mosesschwartz/extract_iocs).
