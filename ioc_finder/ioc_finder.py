#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Python package for finding indicators of compromise in text."""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

import ioc_grammars


def _deduplicate(indicator_list):
    """Deduplicate the list of indicators of compromise."""
    return list(set(indicator_list))


def _listify(indicator_list):
    """Convert the multi-dimensional indicator list into a one-dimensional indicator list with empty entries and duplicates removed."""
    return _deduplicate([indicator[0] for indicator in indicator_list if indicator[0]])


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


def find_iocs(text):
    """Find indicators of compromise in the given text."""
    iocs = dict()

    # urls
    iocs['urls'] = parse_urls(text)
    text = _remove_url_paths(iocs['urls'], text)

    # email addresses
    iocs['email_addresses'] = parse_email_addresses(text)

    # cidr ranges
    iocs['ipv4_cidrs'] = parse_ipv4_cidrs(text)
    # iocs['ipv6_cidrs'] = parse_ipv6_cidrs(text)

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

    return iocs
