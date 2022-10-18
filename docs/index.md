# IOC Finder

[![PyPi](https://img.shields.io/pypi/v/ioc_finder.svg)](https://pypi.python.org/pypi/ioc_finder)
![PyPI - Downloads](https://img.shields.io/pypi/dm/ioc-finder)
[![CI](https://github.com/fhightower/ioc-finder/workflows/CI/badge.svg)](https://github.com/fhightower/ioc-finder/actions)
[![Lint](https://github.com/fhightower/ioc-finder/workflows/Lint/badge.svg)](https://github.com/fhightower/ioc-finder/actions)
[![codecov](https://codecov.io/gh/fhightower/ioc-finder/branch/master/graph/badge.svg)](https://codecov.io/gh/fhightower/ioc-finder)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://choosealicense.com/licenses/lgpl-3.0/)

Welcome to the documentation for the `ioc-finder` library - a library to find different types of [indicators of compromise](https://digitalguardian.com/blog/what-are-indicators-compromise) (a.k.a observables) and data pertinent to indicators of compromise!

📢 *Announcement*: I'm looking for [sponsorship](https://github.com/sponsors/fhightower) for this project. I have a number of improvements and helpful features I'd like to add, but need some support to continue working on this project. If you use this project for work and/or find it useful, please consider [contributing](https://github.com/sponsors/fhightower) even a small amount. Thanks!

## Overview (INTERACTIVE!)

Copy this example and paste it in the terminal below to get an idea of what this package does:

```python
from ioc_finder import find_iocs

text = "This is just an foobar.com https://example.org/test/bingo.php"

iocs = find_iocs(text)
iocs['domains']
iocs['urls']
```

<div id="terminal"></div>

This terminal uses [Pyodide](https://pyodide.org/en/stable/index.html) to provide a Python3.9 runtime in the browser using [WebAssembly](https://webassembly.org/). Enjoy!

## Capabilities

??? info "Data types found by ioc-finder"

    - Autonomous System Numbers (ASNs) (in multiple formats such as `asn1234` and `as 1234`)
    - Bitcoin addresses (P2PKH, P2SH, and Bech32)
    - CIDR ranges (currently ipv4 ranges; ipv6 ranges coming soon)
    - CVEs (e.g. `CVE-2014-1234`)
    - Domain names (support for Unicode domain names (e.g. `ȩxample.com`) is coming soon)
    - Email addresses (both standard format (e.g. `test@example.com`) and an email with an IP address as the domain (e.g. `test@[192.168.0.1]`))
    - File hashes (md5, sha1, sha256, sha512, and [import hashes](https://www.fireeye.com/blog/threat-research/2014/01/ tracking-malware-import-hashing.html), and [authentihashes](http://msdn.microsoft.com/en-us/library/windows/hardware/gg463180.aspx))
    - File paths (*beta*)
    - Google Adsense Publisher IDs
    - Google Analytics Tracker IDs
    - IP address (IPv4 and IPv6)
    - MAC addresses (*beta*)
    - Monero (crypto-currency) addresses
    - Registry key paths (e.g. `"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows`)
    - SSDeep hashes (*beta*)
    - URLs (URLs with and without schemes)
    - User agents (*beta*)
    - XMPP addresses (basically, this captures email addresses whose domain names contain "jabber" or "xmpp")
    - MITRE ATT&CK data (see [more info](https://attack.mitre.org/))\*:
        - Pre-attack tactics and techniques (and [sub-techniques](https://medium.com/mitre-attack/attack-subs-what-you-need-to-know-99bce414ae0b))
        - Enterprise mitigations, tactics, and techniques (and [sub-techniques](https://medium.com/mitre-attack/    attack-subs-what-you-need-to-know-99bce414ae0b))
        - Mobile mitigations, tactics, and techniques (and [sub-techniques](https://medium.com/mitre-attack/    attack-subs-what-you-need-to-know-99bce414ae0b))
    - [TLP labels](https://www.us-cert.gov/tlp)

    Have another data-type you would like ioc-finder to parse? [Raise an issue][issues_link] and we'll see what we can do!

??? info "Configuration Options"

    This library also provides options to:

    - Parse domain name from a URL
    - Parse domain name from an email address
    - Parse IP address from a CIDR range
    - Parse URLs without a scheme (e.g. without `https://`)
    - Parse [import hashes](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html) and [authentihashes](http://msdn.microsoft.com/en-us/library/windows/hardware/gg463180.aspx)

??? info "Known Limitations"

    - When parsing **registry key paths**, this library will NOT properly parse a registry key path where the last section contains a space. For example, `<HKCU>\software\microsoft\windows\currentversion\explorer\advanced on` will be parsed as `<HKCU>\software\microsoft\windows\currentversion\explorer\advanced` (the space in the final section is removed).
    - The items listed above (in the "Capabilities" section) that are postceded by "(*beta*)" are not very robust and may still have major issues. Any feedback or issues related to these items are much appreciated.
    - When parsing **markdown**, if there is a domain name that is surrounded by underscores (which would make the domain name italic in some flavours of markdown - e.g. `_google.com_`), the domain will be parsed *including* the leading underscore (e.g. `_google.com_` would be parsed as `_google.com`).

## Feedback

If you have any ideas to improve this package, please [raise an issue][issues_link]!

## Other Helpful Projects

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

## Credits

This project uses the [ioc_fanger](https://github.com/ioc-fang/ioc_fanger) package to make sure that all indicators in the text are properly [fanged](https://ioc-fanger.hightower.space/).

This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and Floyd Hightower's [python-project-template](https://github.com/fhightower-templates/python-project-template) project template.

[issues_link]: https://github.com/fhightower/ioc-finder/issues

\* -  MITRE data is © 2021 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. (View the MITRE data's [full license](https://github.com/mitre/cti/blob/master/LICENSE.txt))
