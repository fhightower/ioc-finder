#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Python package for finding indicators of compromise in text."""

import json
import os
import sys

import click
import ioc_fanger

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))
import ioc_grammars


def _deduplicate(indicator_list):
    """Deduplicate the list of indicators of compromise."""
    return list(set(indicator_list))


def _listify(indicator_list):
    """Convert the multi-dimensional indicator list into a one-dimensional indicator list with empty entries and duplicates removed."""
    return _deduplicate([indicator[0] for indicator in indicator_list if indicator[0]])


def _remove_items(items, text):
    """Remove each item from the text."""
    for item in items:
        text = text.replace(item, ' ')
    return text


def prepare_text(text):
    """Fang (https://ioc-fang.hightower.space/) and encode the text in such a way that all Unicode domain names are converted into their punycode representation."""
    text = ioc_fanger.fang(text)
    # text = text.encode('idna').decode('utf-8')
    return text


def parse_urls(text, parse_urls_without_scheme=True):
    """."""
    if parse_urls_without_scheme:
        urls = ioc_grammars.scheme_less_url.searchString(text)
    else:
        urls = ioc_grammars.url.searchString(text)
    urls = _listify(urls)

    clean_urls = []

    # clean the url
    for url in urls:
        # remove `"` and `'` characters from the end of a URL
        url = url.rstrip('"').rstrip("'")

        # remove a final ')' if there is a '(' in the url
        if url.endswith(')') and '(' not in url:
            url = url.rstrip(')')

        clean_urls.append(url)

    # return the cleaned urls - I deduplicate them again because the structure of the URL may have changed when it was cleaned
    return _deduplicate(clean_urls)


def _remove_url_paths(urls, text, parse_urls_without_scheme=True):
    """Remove the path from each url from the text."""
    for url in urls:
        if parse_urls_without_scheme:
            parsed_url = ioc_grammars.scheme_less_url.parseString(url)
        else:
            parsed_url = ioc_grammars.url.parseString(url)
        url_path = parsed_url.url_path

        # handle situations where the parsed url is likely a cidr range
        if parse_urls_without_scheme and parse_ipv4_cidrs(str(url)):
            pass
        elif len(url_path) > 1:
            text = text.replace(url_path, ' ')
    return text


def parse_domain_names(text):
    """."""
    domains = ioc_grammars.domain_name.searchString(text)
    return _listify(domains)


def parse_ipv4_addresses(text):
    """."""
    addresses = ioc_grammars.ipv4_address.searchString(text)
    return _listify(addresses)


def parse_ipv6_addresses(text):
    """."""
    addresses = ioc_grammars.ipv6_address.searchString(text)
    return _listify(addresses)


def parse_complete_email_addresses(text):
    """."""
    email_addresses = ioc_grammars.complete_email_address.searchString(text)
    return _listify(email_addresses)


def parse_email_addresses(text):
    """."""
    email_addresses = ioc_grammars.email_address.searchString(text)
    return _listify(email_addresses)


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


def parse_ipv4_cidrs(text):
    """."""
    cidrs = ioc_grammars.ipv4_cidr.searchString(text)
    return _listify(cidrs)


# def parse_ipv6_cidrs(text):
#     """."""
#     # TODO: implement
#     cidrs = ioc_grammars.ipv6_cidr.searchString(text)
#     return _listify(cidrs)


def parse_registry_key_paths(text):
    """."""
    registry_key_paths = ioc_grammars.registry_key_path.searchString(text)
    return _listify(registry_key_paths)


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


def parse_xmpp_addresses(text):
    """."""
    xmpp_addresses = ioc_grammars.xmpp_address.searchString(text)
    return _listify(xmpp_addresses)


def _remove_xmpp_local_part(xmpp_addresses, text):
    """Remove the local part of each xmpp_address from the text."""
    for address in xmpp_addresses:
        text = text.replace(address.split('@')[0] + '@', ' ')

    return text


def parse_mac_addresses(text):
    """."""
    mac_addresses = ioc_grammars.mac_address.searchString(text)
    return _listify(mac_addresses)


@click.command()
@click.argument('text')
@click.option('--no_url_domain_parsing', is_flag=True, help='Using this flag will not parse domain names from URLs')
@click.option(
    '--no_email_addr_domain_parsing',
    is_flag=True,
    help='Using this flag will not parse domain names from email addresses',
)
@click.option(
    '--no_cidr_address_parsing', is_flag=True, help='Using this flag will not parse IP addresses from CIDR ranges'
)
@click.option(
    '--no_xmpp_addr_domain_parsing',
    is_flag=True,
    help='Using this flag will not parse domain names from XMPP addresses',
)
@click.option('--no_urls_without_schemes', is_flag=True, help='Using this flag will not parse URLs without schemes')
def cli_find_iocs(
    text,
    no_url_domain_parsing,
    no_email_addr_domain_parsing,
    no_cidr_address_parsing,
    no_xmpp_addr_domain_parsing,
    no_urls_without_schemes,
):
    """CLI interface for parsing indicators of compromise."""
    iocs = find_iocs(
        text,
        not no_url_domain_parsing,
        not no_email_addr_domain_parsing,
        not no_cidr_address_parsing,
        not no_xmpp_addr_domain_parsing,
        not no_urls_without_schemes,
    )
    ioc_string = json.dumps(iocs, indent=4, sort_keys=True)
    print(ioc_string)


def find_iocs(
    text,
    parse_domain_from_url=True,
    parse_domain_from_email_address=True,
    parse_address_from_cidr=True,
    parse_domain_name_from_xmpp_address=True,
    parse_urls_without_scheme=True,
):
    """Find indicators of compromise in the given text."""
    iocs = dict()

    text = prepare_text(text)

    # urls
    iocs['urls'] = parse_urls(text, parse_urls_without_scheme)
    if not parse_domain_from_url:
        text = _remove_items(iocs['urls'], text)
    # even if we want to parse domain names from the urls, we need to remove the urls' paths to make sure no domain names are incorrectly parsed from the urls' paths
    else:
        text = _remove_url_paths(iocs['urls'], text, parse_urls_without_scheme)

    # xmpp addresses
    iocs['xmpp_addresses'] = parse_xmpp_addresses(text)
    if not parse_domain_name_from_xmpp_address:
        text = _remove_items(iocs['xmpp_addresses'], text)
    # even if we want to parse domain names from the xmpp_address, we don't want them also being caught as email addresses so we'll remove everything before the `@`
    else:
        text = _remove_xmpp_local_part(iocs['xmpp_addresses'], text)

    # complete email addresses
    iocs['complete_email_addresses'] = parse_complete_email_addresses(text)
    if not parse_domain_from_email_address:
        text = _remove_items(iocs['complete_email_addresses'], text)

    # simple email addresses
    iocs['email_addresses'] = parse_email_addresses(text)
    if not parse_domain_from_email_address:
        text = _remove_items(iocs['email_addresses'], text)

    # cidr ranges
    iocs['ipv4_cidrs'] = parse_ipv4_cidrs(text)
    if not parse_address_from_cidr:
        text = _remove_items(iocs['ipv4_cidrs'], text)
    # iocs['ipv6_cidrs'] = parse_ipv6_cidrs(text)
    # if not parse_address_from_cidr:
    # text = _remove_items(iocs['ipv6_cidrs'], text)

    # domains
    iocs['domains'] = parse_domain_names(text)

    # ip addresses
    iocs['ipv4s'] = parse_ipv4_addresses(text)
    iocs['ipv6s'] = parse_ipv6_addresses(text)

    # file hashes
    iocs['sha512s'] = parse_sha512s(text)
    iocs['sha256s'] = parse_sha256s(text)
    iocs['sha1s'] = parse_sha1s(text)
    iocs['md5s'] = parse_md5s(text)
    iocs['ssdeeps'] = parse_ssdeeps(text)

    # misc
    iocs['asns'] = parse_asns(text)
    iocs['cves'] = parse_cves(text)
    iocs['registry_key_paths'] = parse_registry_key_paths(text)
    iocs['google_adsense_publisher_ids'] = parse_google_adsense_ids(text)
    iocs['google_analytics_tracker_ids'] = parse_google_analytics_ids(text)
    iocs['bitcoin_addresses'] = parse_bitcoin_addresses(text)
    iocs['mac_addresses'] = parse_mac_addresses(text)

    return iocs
