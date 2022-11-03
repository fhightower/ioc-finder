"""Python package for finding observables in text."""

import json
import urllib.parse as urlparse
from typing import Callable, Dict, Iterable, List, Mapping, Union

import click
import ioc_fanger
from d8s_strings import string_remove_from_end
from pyparsing import ParseResults

from ioc_finder import ioc_grammars

IndicatorList = List[str]
IndicatorDict = Dict[str, IndicatorList]
# using `Mapping` b/c it is covariant (https://mypy.readthedocs.io/en/stable/generics.html#variance-of-generic-types)
IndicatorData = Mapping[str, Union[IndicatorList, IndicatorDict]]

DEFAULT_IOC_TYPES = [
    "asns",
    "attack_mitigations",
    "attack_tactics",
    "attack_techniques",
    "authentihashes",
    "bitcoin_addresses",
    "cves",
    "domains",
    "email_addresses",
    "email_addresses_complete",
    "file_paths",
    "google_adsense_publisher_ids",
    "google_analytics_tracker_ids",
    "imphashes",
    "ipv4_cidrs",
    "ipv4s",
    "ipv6s",
    "mac_addresses",
    "md5s",
    "monero_addresses",
    "registry_key_paths",
    "sha1s",
    "sha256s",
    "sha512s",
    "ssdeeps",
    "tlp_labels",
    "urls",
    "user_agents",
    "xmpp_addresses",
]


def _deduplicate(indicator_list: Iterable) -> List:
    """Deduplicate the list of observables."""
    return list(set(indicator_list))


def _listify(indicator_list: ParseResults) -> List:
    """Convert the multi-dimensional list into a one-dimensional list with empty entries and duplicates removed."""
    return _deduplicate([indicator[0] for indicator in indicator_list if indicator[0]])


def _remove_items(items: List[str], text: str) -> str:
    """Remove each item from the text."""
    for item in items:
        text = text.replace(item, " ")
    return text


def _get_items(
    iocs: IndicatorData,
    key: str,
    func_if_none: Callable[[str], IndicatorList],
    text: str,
    **kwargs,
) -> IndicatorList:
    data: IndicatorList = iocs.get(key)  # type: ignore
    if data is None:
        data = func_if_none(text, **kwargs)
    return data


def prepare_text(text: str) -> str:
    """Prepare the text for parsing.

    Currently, this involves fanging (https://ioc-fang.hightower.space/) the text."""
    text = ioc_fanger.fang(text)
    # text = text.encode('idna').decode('utf-8')
    return text


def _clean_url(url: str) -> str:
    """Clean the given URL, removing common, unwanted characters which are usually not part of the URL."""
    # if there is a ")" in the URL and not a "(", remove everything including and after the ")"
    if ")" in url and "(" not in url:
        url = url.split(")")[0]

    # remove `"` and `'` characters from the end of a URL
    url = url.rstrip('"').rstrip("'")

    # remove `'/>` and `"/>` from the end of a URL (this character string occurs at the end of an HMTL tag with )
    url = string_remove_from_end(url, "'/>")
    url = string_remove_from_end(url, '"/>')

    return url


def parse_urls(text: str, *, parse_urls_without_scheme: bool = True) -> List:
    """."""
    if parse_urls_without_scheme:
        url_parse_results = ioc_grammars.scheme_less_url.searchString(text)
    else:
        url_parse_results = ioc_grammars.url.searchString(text)
    urls = _listify(url_parse_results)

    clean_urls = map(_clean_url, urls)

    # I deduplicate them again because the structure of the URL may have changed when it was cleaned
    return _deduplicate(clean_urls)


def _remove_url_domain_name(urls: List, text) -> str:
    """Remove the domain name of each url from the text."""
    for url in urls:
        parsed_url = ioc_grammars.scheme_less_url.parseString(url)
        text = text.replace(parsed_url.url_authority, " ")
    return text


def _remove_url_paths(urls: List, text: str) -> str:
    """Remove the path of each url from the text."""
    for url in urls:
        parsed_url = ioc_grammars.scheme_less_url.parseString(url)
        url_path = urlparse.unquote_plus(parsed_url.url_path)

        is_cidr_range = parse_ipv4_cidrs(str(url))
        # if the 'url' has a URL path and is not a cidr range, remove the url_path
        if not is_cidr_range and len(url_path) > 1:
            text = text.replace(url_path, " ")
    return text


def _percent_decode_url(urls: List, text: str) -> str:
    for url in urls:
        text = text.replace(url, urlparse.unquote_plus(url))
    return text


def parse_domain_names(text):
    """."""
    domains = ioc_grammars.domain_name.searchString(text.lower())
    return _listify(domains)


def parse_ipv4_addresses(text):
    """."""
    addresses = ioc_grammars.ipv4_address.searchString(text)
    return _listify(addresses)


def parse_ipv6_addresses(text):
    """."""
    addresses = ioc_grammars.ipv6_address.searchString(text)
    return _listify(addresses)


def parse_complete_email_addresses(text: str) -> List:
    """."""
    email_addresses = ioc_grammars.complete_email_address.searchString(text)
    return _listify(email_addresses)


def parse_email_addresses(text: str) -> List:
    """."""
    email_addresses = ioc_grammars.email_address.searchString(text)
    return _listify(email_addresses)


# there is a trailing underscore on this function to differentiate it from the argument with the same name
def parse_imphashes_(text: str) -> List:
    """."""
    full_imphash_instances = _listify(ioc_grammars.imphash.searchString(text.lower()))

    imphashes = []

    for imphash in full_imphash_instances:
        imphashes.append(ioc_grammars.imphash.parseString(imphash).hash[0])

    return imphashes


# there is a trailing underscore on this function to differentiate it from the argument with the same name
def parse_authentihashes_(text: str) -> List:
    """."""
    full_authentihash_instances = _listify(ioc_grammars.authentihash.searchString(text.lower()))

    authentihashes = []

    for authentihash in full_authentihash_instances:
        authentihashes.append(ioc_grammars.authentihash.parseString(authentihash).hash[0])

    return authentihashes


def parse_md5s(text):
    """."""
    md5s = ioc_grammars.md5.searchString(text)
    return _listify(md5s)


def parse_sha1s(text):
    """."""
    sha1s = ioc_grammars.sha1.searchString(text)
    return _listify(sha1s)


def parse_sha256s(text):
    """."""
    sha256s = ioc_grammars.sha256.searchString(text)
    return _listify(sha256s)


def parse_sha512s(text):
    """."""
    sha512s = ioc_grammars.sha512.searchString(text)
    return _listify(sha512s)


def parse_ssdeeps(text):
    """."""
    ssdeeps = ioc_grammars.ssdeep.searchString(text)
    return _listify(ssdeeps)


def parse_asns(text):
    """."""
    asns = ioc_grammars.asn.searchString(text)
    return _listify(asns)


def parse_cves(text):
    """."""
    cves = ioc_grammars.cve.searchString(text)
    return _listify(cves)


def parse_ipv4_cidrs(text: str) -> List:
    """."""
    cidrs = ioc_grammars.ipv4_cidr.searchString(text)
    return _listify(cidrs)


def parse_registry_key_paths(text):
    """."""
    parsed_registry_key_paths = ioc_grammars.registry_key_path.searchString(text)
    full_parsed_registry_key_paths = _listify(parsed_registry_key_paths)

    registry_key_paths = []
    for registry_key_path in full_parsed_registry_key_paths:
        # if there is a space in the last section of the parsed registry key path,
        # remove it so that content after a registry key path is not also pulled in...
        # this is a limitation of the grammar:
        # it will not parse a registry key path with a space in the final section (the section after the final '\')
        if " " in registry_key_path.split("\\")[-1]:
            last_section = registry_key_path.split("\\")[-1]
            registry_key_path = registry_key_path.replace(last_section, last_section.split(" ")[0])
            registry_key_paths.append(registry_key_path)
        else:
            registry_key_paths.append(registry_key_path)

    return registry_key_paths


def parse_google_adsense_ids(text):
    """."""
    adsense_publisher_ids = ioc_grammars.google_adsense_publisher_id.searchString(text)
    return _listify(adsense_publisher_ids)


def parse_google_analytics_ids(text):
    """."""
    analytics_tracker_ids = ioc_grammars.google_analytics_tracker_id.searchString(text)
    return _listify(analytics_tracker_ids)


def parse_bitcoin_addresses(text):
    """."""
    bitcoin_addresses = ioc_grammars.bitcoin_address.searchString(text)
    return _listify(bitcoin_addresses)


def parse_monero_addresses(text):
    """."""
    monero_addresses = ioc_grammars.monero_address.searchString(text)
    return _listify(monero_addresses)


def parse_xmpp_addresses(text: str) -> List:
    """."""
    xmpp_addresses = ioc_grammars.xmpp_address.searchString(text)
    return _listify(xmpp_addresses)


def _remove_xmpp_local_part(xmpp_addresses: List, text: str) -> str:
    """Remove the local part of each xmpp_address from the text."""
    for address in xmpp_addresses:
        text = text.replace(address.split("@")[0] + "@", " ")

    return text


def parse_mac_addresses(text):
    """."""
    mac_addresses = ioc_grammars.mac_address.searchString(text)
    return _listify(mac_addresses)


def parse_user_agents(text):
    """."""
    user_agents = ioc_grammars.user_agent.searchString(text)
    return _listify(user_agents)


def parse_file_paths(text):
    """."""
    file_paths = ioc_grammars.file_path.searchString(text)
    return _listify(file_paths)


def parse_pre_attack_tactics(text):
    """."""
    data = ioc_grammars.pre_attack_tactics_grammar.searchString(text)
    return _listify(data)


def parse_pre_attack_techniques(text):
    """."""
    data = ioc_grammars.pre_attack_techniques_grammar.searchString(text)
    return _listify(data)


def parse_enterprise_attack_mitigations(text):
    """."""
    data = ioc_grammars.enterprise_attack_mitigations_grammar.searchString(text)
    return _listify(data)


def parse_enterprise_attack_tactics(text):
    """."""
    data = ioc_grammars.enterprise_attack_tactics_grammar.searchString(text)
    return _listify(data)


def parse_enterprise_attack_techniques(text):
    """."""
    data = ioc_grammars.enterprise_attack_techniques_grammar.searchString(text)
    return _listify(data)


def parse_mobile_attack_mitigations(text):
    """."""
    data = ioc_grammars.mobile_attack_mitigations_grammar.searchString(text)
    return _listify(data)


def parse_mobile_attack_tactics(text):
    """."""
    data = ioc_grammars.mobile_attack_tactics_grammar.searchString(text)
    return _listify(data)


def parse_mobile_attack_techniques(text):
    """."""
    data = ioc_grammars.mobile_attack_techniques_grammar.searchString(text)
    return _listify(data)


def parse_tlp_labels(text):
    """."""
    tlp_labels = ioc_grammars.tlp_label.searchString(text)
    return _listify(tlp_labels)


@click.command()
@click.argument("text", required=False)
@click.option("--no_url_domain_parsing", is_flag=True, help="Using this flag will not parse domain names from URLs")
@click.option(
    "--no_parse_from_url_path", is_flag=True, help="Using this flag will not parse observables from URL paths"
)
@click.option(
    "--no_email_addr_domain_parsing",
    is_flag=True,
    help="Using this flag will not parse domain names from email addresses",
)
@click.option(
    "--no_cidr_address_parsing", is_flag=True, help="Using this flag will not parse IP addresses from CIDR ranges"
)
@click.option(
    "--no_xmpp_addr_domain_parsing",
    is_flag=True,
    help="Using this flag will not parse domain names from XMPP addresses",
)  # pylint: disable=R0913
@click.option(
    "--parse_urls_without_scheme",
    is_flag=True,
    help="Using this flag will parse URLs with and without a scheme (default is True)",
    default=True,
)
@click.option("--no_import_hashes", is_flag=True, help="Using this flag will not parse import hashes")
@click.option("--no_authentihashes", is_flag=True, help="Using this flag will not parse authentihashes")
def cli_find_iocs(
    text,
    no_url_domain_parsing,
    no_parse_from_url_path,
    no_email_addr_domain_parsing,
    no_cidr_address_parsing,
    no_xmpp_addr_domain_parsing,
    parse_urls_without_scheme,
    no_import_hashes,
    no_authentihashes,
):
    """CLI interface for parsing observables."""
    stdin_text = click.get_text_stream("stdin")

    # if there is stdin, use it
    if not text and stdin_text:
        text = "\n".join(stdin_text)
        # text = '\n'.join([line for line in stdin_text])

    iocs = find_iocs(
        text,
        parse_domain_from_url=not no_url_domain_parsing,
        parse_from_url_path=not no_parse_from_url_path,
        parse_domain_from_email_address=not no_email_addr_domain_parsing,
        parse_address_from_cidr=not no_cidr_address_parsing,
        parse_domain_name_from_xmpp_address=not no_xmpp_addr_domain_parsing,
        parse_urls_without_scheme=parse_urls_without_scheme,
        parse_imphashes=not no_import_hashes,
        parse_authentihashes=not no_authentihashes,
    )
    ioc_string = json.dumps(iocs, indent=4, sort_keys=True)
    print(ioc_string)


def find_iocs(  # noqa: CCR001 pylint: disable=R0912,R0915
    text: str,
    *,
    parse_domain_from_url: bool = True,
    parse_from_url_path: bool = True,
    parse_domain_from_email_address: bool = True,
    parse_address_from_cidr: bool = True,
    parse_domain_name_from_xmpp_address: bool = True,
    parse_urls_without_scheme: bool = True,
    parse_imphashes: bool = True,
    parse_authentihashes: bool = True,
    included_ioc_types: List[str] = DEFAULT_IOC_TYPES,
) -> IndicatorData:
    """Find observables (a.k.a. indicators of compromise) in the given text."""
    iocs = {}

    text = prepare_text(text)
    # keep a copy of the original text - some items should be parsed from the original text
    original_text = text

    # urls
    if "urls" in included_ioc_types:
        iocs["urls"] = parse_urls(text, parse_urls_without_scheme=parse_urls_without_scheme)
        if not parse_domain_from_url and not parse_from_url_path:
            text = _remove_items(iocs["urls"], text)
        elif not parse_domain_from_url:
            text = _percent_decode_url(iocs["urls"], text)
            text = _remove_url_domain_name(iocs["urls"], text)
        elif not parse_from_url_path:
            text = _percent_decode_url(iocs["urls"], text)
            text = _remove_url_paths(iocs["urls"], text)
        else:
            text = _percent_decode_url(iocs["urls"], text)

    # xmpp addresses
    if "xmpp_addresses" in included_ioc_types:
        iocs["xmpp_addresses"] = parse_xmpp_addresses(text)

    if "domains" in included_ioc_types and not parse_domain_name_from_xmpp_address:
        xmpp_addresses = _get_items(iocs, "xmpp_addresses", parse_xmpp_addresses, text)
        text = _remove_items(xmpp_addresses, text)
    # even if we want to parse domain names from the xmpp_address,
    # we don't want them also being caught as email addresses so we'll remove everything before the `@`
    elif "email_addresses_complete" in included_ioc_types or "email_addresses" in included_ioc_types:
        xmpp_addresses = _get_items(iocs, "xmpp_addresses", parse_xmpp_addresses, text)
        text = _remove_xmpp_local_part(xmpp_addresses, text)

    # complete email addresses
    if "email_addresses_complete" in included_ioc_types:
        iocs["email_addresses_complete"] = parse_complete_email_addresses(text)
    if "email_addresses" in included_ioc_types:
        iocs["email_addresses"] = parse_email_addresses(text)

    if not parse_domain_from_email_address:
        email_addresses_complete = _get_items(iocs, "email_addresses_complete", parse_complete_email_addresses, text)
        email_addresses = _get_items(iocs, "email_addresses", parse_email_addresses, text)

        text = _remove_items(email_addresses_complete, text)
        text = _remove_items(email_addresses, text)

    if "ipv6s" in included_ioc_types:
        # after parsing the email addresses, we need to remove the
        # '[IPv6:' bit from any of the email addresses so that ipv6 addresses are not extraneously parsed
        text = _remove_items(["[IPv6:"], text)

    # cidr ranges
    if "ipv4_cidrs" in included_ioc_types:
        iocs["ipv4_cidrs"] = parse_ipv4_cidrs(text)

    # remove URLs that are also ipv4_cidrs (see https://github.com/fhightower/ioc-finder/issues/91)
    url_parsing_requires_cidr_removal = "urls" in included_ioc_types and parse_urls_without_scheme
    ip_address_parsing_requires_cidr_removal = "ipv4s" in included_ioc_types and not parse_address_from_cidr
    if url_parsing_requires_cidr_removal or ip_address_parsing_requires_cidr_removal:
        cidr_ranges = _get_items(iocs, "ipv4_cidrs", parse_ipv4_cidrs, text)
        if url_parsing_requires_cidr_removal:
            for cidr in cidr_ranges:
                if cidr in iocs["urls"]:
                    iocs["urls"].remove(cidr)
        if ip_address_parsing_requires_cidr_removal:
            text = _remove_items(cidr_ranges, text)

    # file hashes
    if "imphashes" in included_ioc_types:
        if parse_imphashes:
            iocs["imphashes"] = parse_imphashes_(text)
    if "md5s" in included_ioc_types:
        # remove the imphashes so they are not also parsed as md5s
        imphashes = _get_items(iocs, "imphashes", parse_imphashes_, text)
        text = _remove_items(imphashes, text)

    if "authentihashes" in included_ioc_types:
        if parse_authentihashes:
            iocs["authentihashes"] = parse_authentihashes_(text)
    if "sha256s" in included_ioc_types:
        # remove the authentihashes so they are not also parsed as sha256s
        authentihashes = _get_items(iocs, "authentihashes", parse_authentihashes_, text)
        text = _remove_items(authentihashes, text)

    # domains
    if "domains" in included_ioc_types:
        iocs["domains"] = parse_domain_names(text)

    # ip addresses
    if "ipv4s" in included_ioc_types:
        iocs["ipv4s"] = parse_ipv4_addresses(text)
    if "ipv6s" in included_ioc_types:
        iocs["ipv6s"] = parse_ipv6_addresses(text)

    # file hashes
    if "sha512s" in included_ioc_types:
        iocs["sha512s"] = parse_sha512s(text)
    if "sha256s" in included_ioc_types:
        iocs["sha256s"] = parse_sha256s(text)
    if "sha1s" in included_ioc_types:
        iocs["sha1s"] = parse_sha1s(text)
    if "md5s" in included_ioc_types:
        iocs["md5s"] = parse_md5s(text)
    if "ssdeeps" in included_ioc_types:
        iocs["ssdeeps"] = parse_ssdeeps(text)

    # misc
    if "asns" in included_ioc_types:
        iocs["asns"] = parse_asns(text)
    if "cves" in included_ioc_types:
        iocs["cves"] = parse_cves(original_text)
    if "registry_key_paths" in included_ioc_types:
        iocs["registry_key_paths"] = parse_registry_key_paths(text)
    if "google_adsense_publisher_ids" in included_ioc_types:
        iocs["google_adsense_publisher_ids"] = parse_google_adsense_ids(text)
    if "google_analytics_tracker_ids" in included_ioc_types:
        iocs["google_analytics_tracker_ids"] = parse_google_analytics_ids(text)
    if "bitcoin_addresses" in included_ioc_types:
        iocs["bitcoin_addresses"] = parse_bitcoin_addresses(text)
    if "monero_addresses" in included_ioc_types:
        iocs["monero_addresses"] = parse_monero_addresses(text)
    if "mac_addresses" in included_ioc_types:
        iocs["mac_addresses"] = parse_mac_addresses(text)
    if "user_agents" in included_ioc_types:
        iocs["user_agents"] = parse_user_agents(text)
    if "tlp_labels" in included_ioc_types:
        iocs["tlp_labels"] = parse_tlp_labels(original_text)

    if "attack_mitigations" in included_ioc_types:
        iocs["attack_mitigations"] = {  # type: ignore
            "enterprise": parse_enterprise_attack_mitigations(original_text),
            "mobile": parse_mobile_attack_mitigations(original_text),
        }

    if "attack_tactics" in included_ioc_types:
        iocs["attack_tactics"] = {  # type: ignore
            "pre_attack": parse_pre_attack_tactics(original_text),
            "enterprise": parse_enterprise_attack_tactics(original_text),
            "mobile": parse_mobile_attack_tactics(original_text),
        }

    if "attack_techniques" in included_ioc_types:
        iocs["attack_techniques"] = {  # type: ignore
            "pre_attack": parse_pre_attack_techniques(original_text),
            "enterprise": parse_enterprise_attack_techniques(original_text),
            "mobile": parse_mobile_attack_techniques(original_text),
        }

    if "file_paths" in included_ioc_types:
        # if there are still url paths in the text, remove them so they don't get parsed as file names
        if parse_from_url_path:
            urls = _get_items(iocs, "urls", parse_urls, text, parse_urls_without_scheme=parse_urls_without_scheme)
            text = _remove_url_paths(urls, text)

        iocs["file_paths"] = parse_file_paths(text)

    return iocs
