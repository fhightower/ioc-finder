# IOC Finder

[![PyPi](https://img.shields.io/pypi/v/ioc_finder.svg)](https://pypi.python.org/pypi/ioc_finder)

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/4078c4e3e384431bbe69c35c7f6da7b7)](https://www.codacy.com/app/fhightower/ioc-finder)

[![Build Status](https://travis-ci.org/fhightower/ioc-finder.svg?branch=master)](https://travis-ci.org/fhightower/ioc-finder)

[![codecov](https://codecov.io/gh/fhightower/ioc-finder/branch/master/graph/badge.svg)](https://codecov.io/gh/fhightower/ioc-finder)

Parse [indicators of compromise](https://searchsecurity.techtarget.com/definition/Indicators-of-Compromise-IOC) in text.

## Capabilities

Currently, this package can the following items in a given text:

- IP address (IPv4 and IPv6)
- Email addresses (both standard format (e.g. ``test@example.com``) and an email with an IP address as the domain (e.g. ``test@[192.168.0.1]``))
- Hosts (including unicode domain names (e.g. ``ȩxample.com``))
- URLs
- File Hashes (sha256, sha1, and md5)

Also provides some helpful features like:

- Ability to remove an indicator type after it is parsed - For example, this is helpful if you do not want to parse the host name from a URL. You can setup IOC Finder to remove all URLs from the text after it parses them.
- Ability to set order in which IOCs are parsed

## Installation

To install this package:

```
pip install ioc-finder
```

## Usage

To use this package:

```python
from ioc_finder import find_iocs
text = "This is just an example.com"
iocs = find_iocs(text)
print('Domains: {}'.format(iocs['domain']))
```

See [test_ioc_finder.py](https://github.com/fhightower/ioc-finder/blob/master/tests/test_ioc_finder.py) for more examples.

## Credits

Many of the elements of this package also exist in [https://github.com/mosesschwartz/extract_iocs](https://github.com/mosesschwartz/extract_iocs) which I've contributed to in the past.

This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and Floyd Hightower's [python-project-template](https://gitlab.com/fhightower-templates/python-project-template) project template.
