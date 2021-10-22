## Installation

The recommended means of installation is using [pip](https://pypi.python.org/pypi/pip/):

`pip install ioc-finder`

Alternatively, you can install ioc-finder as follows:

```shell
git clone git@github.com:fhightower/ioc-finder.git && cd ioc-finder;
python setup.py install --user;
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
- `parse_from_url_path` (default=True): Whether or not to parse observables from URL paths (e.g. `2f3ec0e4998909bb0efab13c82d30708ca9f88679e42b75ef13ea0466951d862` from `https://www.virustotal.com/gui/file/2f3ec0e4998909bb0efab13c82d30708ca9f88679e42b75ef13ea0466951d862/detection`)
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
    "attack_mitigations": {
        "enterprise": [],
        "mobile": []
    },
    "attack_tactics": {
        "enterprise": [],
        "mobile": [],
        "pre_attack": []
    },
    "attack_techniques": {
        "enterprise": [],
        "mobile": [],
        "pre_attack": []
    },
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
    "md5s": [],
    "monero_addresses": [],
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
    "attack_mitigations": {
        "enterprise": [],
        "mobile": []
    },
    "attack_tactics": {
        "enterprise": [],
        "mobile": [],
        "pre_attack": []
    },
    "attack_techniques": {
        "enterprise": [],
        "mobile": [],
        "pre_attack": []
    },
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
    "md5s": [],
    "monero_addresses": [],
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

### Parsing Specific Indicator Types

If you need to parse a specific indicator type, you can do this using one of the parse functions that start with `parse_`. For example, the code below will parse URLs:

```python
from ioc_finder import parse_urls

text = 'https://google.com'
results = parse_urls(prepare_text(text))
print(results)
```

If you use a parse function for a specific indicator type, we recommend that you first call the `prepare_text` function which [fangs](https://ioc-fanger.hightower.space/) (e.g. `hXXps://example[.]com` => `https://example.com`) the text before parsing indicators from it. In the future, more functionality will be added to the `prepare_text` function making it advantageous to call this function before parsing indicators.

### Command-Line Interface

The ioc-finder package can be used from a command line like:

```
ioc-finder "This is just an example.com https://example.org/test/bingo.php"
```

This will return:

```json
{
    "asns": [],
    "attack_mitigations": {
        "enterprise": [],
        "mobile": []
    },
    "attack_tactics": {
        "enterprise": [],
        "mobile": [],
        "pre_attack": []
    },
    "attack_techniques": {
        "enterprise": [],
        "mobile": [],
        "pre_attack": []
    },
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
    "md5s": [],
    "monero_addresses": [],
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
