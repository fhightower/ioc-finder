# IOC Finder

[![PyPi](https://img.shields.io/pypi/v/ioc_finder.svg)](https://pypi.python.org/pypi/ioc_finder)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/4078c4e3e384431bbe69c35c7f6da7b7)](https://www.codacy.com/app/fhightower/ioc-finder)
[![Build Status](https://travis-ci.org/fhightower/ioc-finder.svg?branch=master)](https://travis-ci.org/fhightower/ioc-finder)
[![codecov](https://codecov.io/gh/fhightower/ioc-finder/branch/master/graph/badge.svg)](https://codecov.io/gh/fhightower/ioc-finder)

Parse [indicators of compromise](https://searchsecurity.techtarget.com/definition/Indicators-of-Compromise-IOC) from text. You can test this project here: [http://ioc-finder.hightower.space/](http://ioc-finder.hightower.space/).

## Capabilities

Currently, this package can the following items in a given text:

- Autonomous System Numbers (ASNs) (in multiple formats such as `asn1234` and `as 1234`)
- Bitcoin addresses (P2PKH, P2SH, and Bech32)
- CIDR ranges (currently ipv4 ranges; ipv6 ranges coming soon)
- CVEs (e.g. `CVE-2014-1234`)
- Domain names (support for Unicode domain names (e.g. `ȩxample.com`) is coming soon)
- Email addresses (both standard format (e.g. `test@example.com`) and an email with an IP address as the domain (e.g. `test@[192.168.0.1]`))
- File hashes (md5, sha1, sha256, sha512, and [import hashes](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html), and [authentihashes](http://msdn.microsoft.com/en-us/library/windows/hardware/gg463180.aspx))
- File paths (*beta*)
- Google Adsense Publisher IDs
- Google Analytics Tracker IDs
- IP address (IPv4 and IPv6)
- MAC addresses (*beta*)
- Phone numbers (*beta*)
- Registry key paths (e.g. `"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows`)
- SSDeep hashes (*beta*)
- URLs (URLs with and without schemes)
- User agents (*beta*)
- XMPP addresses (basically, this captures email addresses whose domain names contain "jabber" or "xmpp")
- MITRE ATT&CK tactics and techniques (see [more info](https://attack.mitre.org/))
- [TLP labels](https://www.us-cert.gov/tlp)
- Malware names
- Others... if you have any requests, [let me know](https://github.com/fhightower/ioc-finder) (or you can contact me [here](https://hightower.space/contact/) to make private suggestions)!

Also provides some helpful features like:

- Option to parse domain name from a URL
- Option to parse domain name from an email address
- Option to parse IP address from a CIDR range
- Option to parse URLs without a scheme (e.g. without `https://`)
- Option to parse [import hashes](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html) and [authentihashes](http://msdn.microsoft.com/en-us/library/windows/hardware/gg463180.aspx)

## Known Limitations

- When parsing **registry key paths**, this library will NOT properly parse a registry key path where the last section contains a space. For example, `<HKCU>\software\microsoft\windows\currentversion\explorer\advanced on` will be parsed as `<HKCU>\software\microsoft\windows\currentversion\explorer\advanced` (the space in the final section is removed).
- The items listed above (in the "Capabilities" section) that are postceded by "(*beta*)" are not very robust and may still have major issues. Any feedback or issues related to these items are much appreciated.
- When parsing **markdown**, if there is a domain name that is surrounded by underscores (which would make the domain name italic in some flavours of markdown - e.g. `_google.com_`), the domain will be parsed *including* the leading underscore (e.g. `_google.com_` would be parsed as `_google.com`).

## Python2 Support

All versions of the IOC Finder package *before* version 2.x are compatible with python2.7 . **Beware: version 1.x of the IOC Finder package is no longer maintained.** This means that any bug fixes or improvements will **not** be back-ported to previous versions.

To install a specific version of the IOC Finder package (or any other one) via pip, use the following formula:

```
pip install ioc-finder==<VERSION NUMBER>
```

For example:

```
pip install ioc-finder==1.2.18
```

## Installation

To install this package:

```
pip install ioc-finder
```

## Usage

This package can be used in [python](#python) or via a [command-line interface](#command-line-interface).

### Python

The primary function in this package is the `ioc_finder.find_iocs()` function. A simple usage looks like:

```python
from ioc_finder import find_iocs
text = "This is just an example.com https://example.org/test/bingo.php"
iocs = find_iocs(text)
print('Domains: {}'.format(iocs['domains']))
print('URLs: {}'.format(iocs['urls']))
```

#### Inputs

You must pass some text into the `find_iocs()` function as string (the iocs will be parsed from this text). You can also provide the options detailed below.

##### Options

The `find_iocs` takes the following keywords (all of them default to `True`):

- `parse_domain_from_url` (default=True): Whether or not to parse domain names from URLs (e.g. `example.com` from `https://example.com/test`)
- `parse_domain_from_email_address` (default=True): Whether or not to parse domain names from email addresses (e.g. `example.com` from `foo@example.com`)
- `parse_address_from_cidr` (default=True): Whether or not to parse IP addresses from CIDR ranges (e.g. `0.0.0.1` from `0.0.0.1/24`)
- `parse_urls_without_scheme` (default=True): Whether or not to parse URLs without a scheme (see [https://en.wikipedia.org/wiki/Uniform_Resource_Identifier#Generic_syntax](https://en.wikipedia.org/wiki/Uniform_Resource_Identifier#Generic_syntax)) (e.g. `hightower.space/projects`)
- `parse_imphashes` (default=True): Parse [import hashes](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html) (which look like md5s, but are preceded by 'imphash' or 'import hash')
- `parse_authentihashes` (default=True): Parse [authentihashes](http://msdn.microsoft.com/en-us/library/windows/hardware/gg463180.aspx) (which look like sha256s, but are preceded with 'authentihash')

See [test_ioc_finder.py](https://github.com/fhightower/ioc-finder/blob/master/tests/test_ioc_finder.py) for more examples.

#### Output

The `find_iocs()` returns a dictionary in the following structure:

```json
{
    "asns": [],
    "attack_tactics": [],
    "attack_techniques": [],
    "authentihashes": [],
    "bitcoin_addresses": [],
    "cves": [],
    "domains": [],
    "email_addresses": [],
    "email_addresses_complete": [],
    "file_paths": [],
    "google_adsense_publisher_ids": [],
    "google_analytics_tracker_ids": [],
    "imphashes": [],
    "ipv4_cidrs": [],
    "ipv4s": [],
    "ipv6s": [],
    "mac_addresses": [],
    "malware_names": [],
    "md5s": [],
    "phone_numbers": [],
    "registry_key_paths": [],
    "sha1s": [],
    "sha256s": [],
    "sha512s": [],
    "ssdeeps": [],
    "tlp_labels": [],
    "urls": [],
    "user_agents": [],
    "xmpp_addresses": []
}
```

For example, running the example code shown at the start of the [usage](#usage) section above produces the following output:

```json
{
    "asns": [],
    "attack_tactics": [],
    "attack_techniques": [],
    "authentihashes": [],
    "bitcoin_addresses": [],
    "cves": [],
    "domains": ["example.org", "example.com"],
    "email_addresses": [],
    "email_addresses_complete": [],
    "file_paths": [],
    "google_adsense_publisher_ids": [],
    "google_analytics_tracker_ids": [],
    "imphashes": [],
    "ipv4_cidrs": [],
    "ipv4s": [],
    "ipv6s": [],
    "mac_addresses": [],
    "malware_names": [],
    "md5s": [],
    "phone_numbers": [],
    "registry_key_paths": [],
    "sha1s": [],
    "sha256s": [],
    "sha512s": [],
    "ssdeeps": [],
    "tlp_labels": [],
    "urls": ["https://example.org/test/bingo.php"],
    "user_agents": [],
    "xmpp_addresses": []
}
```

##### Output Details

There are two grammars for email addresses. There is a fairly complete grammar to find email addresses matching the spec (which is very broad). Any of these complete email addresses (e.g. `foo"bar@gmail.com`) will be sent as output to in `email_addresses_complete` key.

Email addresses in the simple form we are familiar with (e.g. `bar@gmail.com`) will be sent as output in the `email_addresses` key.

### Command-Line Interface

The ioc-finder package can be used from a command line like:

```
ioc-finder "This is just an example.com https://example.org/test/bingo.php"
```

This will return:

```json
{
    "asns": [],
    "attack_tactics": [],
    "attack_techniques": [],
    "authentihashes": [],
    "bitcoin_addresses": [],
    "cves": [],
    "domains": [
        "example.com",
        "example.org"
    ],
    "email_addresses": [],
    "email_addresses_complete": [],
    "file_paths": [],
    "google_adsense_publisher_ids": [],
    "google_analytics_tracker_ids": [],
    "imphashes": [],
    "ipv4_cidrs": [],
    "ipv4s": [],
    "ipv6s": [],
    "mac_addresses": [],
    "malware_names": [],
    "md5s": [],
    "phone_numbers": [],
    "registry_key_paths": [],
    "sha1s": [],
    "sha256s": [],
    "sha512s": [],
    "ssdeeps": [],
    "tlp_labels": [],
    "urls": [
        "https://example.org/test/bingo.php"
    ],
    "user_agents": [],
    "xmpp_addresses": []
}
```

Here are the usage instructions for the CLI:

```
Usage: ioc-finder [OPTIONS] TEXT

  CLI interface for parsing indicators of compromise.

Options:
  --no_url_domain_parsing         Using this flag will not parse domain names
                                  from URLs
  --no_email_addr_domain_parsing  Using this flag will not parse domain names
                                  from email addresses
  --no_cidr_address_parsing       Using this flag will not parse IP addresses
                                  from CIDR ranges
  --no_xmpp_addr_domain_parsing   Using this flag will not parse domain names
                                  from XMPP addresses
  --help                          Show this message and exit.
```

### Parsing Specific Indicator Types

If you need to parse a specific indicator type, you can do this using one of the parse functions that start with `parse_`. For example, the code below will parse URLs:

```python
from ioc_finder import parse_urls
results = parse_urls('https://google.com')
print(results)
```

**Warning:** It is recommended that you use the `ioc_finder.find_iocs` function rather than a parse function as `ioc_finder.find_iocs` handles some of the nuances of parsing indicator data. If you use specific functions, the text you provide will **not** be [fanged](https://ioc-fang.hightower.space/) and may not return the data you expect.

## Credits

This project uses the [ioc_fanger](https://github.com/ioc-fang/ioc_fanger) package to make sure that all indicators in the text are properly [fanged](https://ioc-fang.hightower.space/).

This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and Floyd Hightower's [python-project-template](https://gitlab.com/fhightower-templates/python-project-template) project template.

Previous iterations of this package were inspired by [https://github.com/mosesschwartz/extract_iocs](https://github.com/mosesschwartz/extract_iocs).

### Other Helpful Projects

You may also be interested in [https://github.com/ioc-fang/ioc_fanger](https://github.com/ioc-fang/ioc_fanger), a project to fang and defang indicators of compromise. For example,

defanging:

```
example.com => example[.]com
https://example.com => hXXps://example[.]com
```

and fanging:

```
example[.]com => example.com
example(.)com => example.com
me AT example(.)com => me@example.com
```

### Similar Projects

There are a number of projects available to find Indicators of Compromise. Your mileage may vary with them. If there are things that another package can do that you would like to see in this package, [let me know](https://github.com/fhightower/ioc-finder/issues) (or [contact me](https://hightower.space/contact/)). Here are a few other ones:

- [https://github.com/InQuest/python-iocextract](https://github.com/InQuest/python-iocextract)
- [https://github.com/sroberts/cacador](https://github.com/sroberts/cacador)
- [https://github.com/armbues/ioc_parser](https://github.com/armbues/ioc_parser)
