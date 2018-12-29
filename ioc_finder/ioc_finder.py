#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Python package for finding indicators of compromise in text."""

import os
import sys

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


def parse_urls(text):
    """."""
    urls = ioc_grammars.url.searchString(text)
    return _listify(urls)


def _remove_url_paths(urls, text):
    """Remove the path from each url from the text."""
    for url in urls:
        parsed_url = ioc_grammars.url.parseString(url)
        url_path = parsed_url.url_path

        if len(url_path) > 1:
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


def parse_email_addresses(text):
    """."""
    email_addresses = ioc_grammars.email_address.searchString(text)
    return _listify(email_addresses)


def parse_simple_email_addresses(text):
    """."""
    simple_email_addresses = ioc_grammars.simple_email_address.searchString(text)
    return _listify(simple_email_addresses)


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


def find_iocs(text, parse_host_from_url=True, parse_host_from_email=True, parse_address_from_cidr=True):
    """Find indicators of compromise in the given text."""
    iocs = dict()

    text = prepare_text(text)

    # urls
    iocs['urls'] = parse_urls(text)
    if not parse_host_from_url:
        text = _remove_items(iocs['urls'], text)
    # even if we want to parse hosts from the urls, we need to remove the urls' paths to make sure no domain names are incorrectly parsed from the urls' paths
    else:
        text = _remove_url_paths(iocs['urls'], text)

    # email addresses
    iocs['email_addresses'] = parse_email_addresses(text)
    if not parse_host_from_email:
        text = _remove_items(iocs['email_addresses'], text)

    # simple addresses
    iocs['simple_email_addresses'] = parse_simple_email_addresses(text)
    if not parse_host_from_email:
        text = _remove_items(iocs['simple_email_addresses'], text)

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

    # misc
    iocs['asns'] = parse_asns(text)
    iocs['cves'] = parse_cves(text)
    iocs['registry_key_paths'] = parse_registry_key_paths(text)
    iocs['google_adsense_publisher_ids'] = parse_google_adsense_ids(text)
    iocs['google_analytics_tracker_ids'] = parse_google_analytics_ids(text)
    iocs['bitcoin_addresses'] = parse_bitcoin_addresses(text)

    return iocs
