#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test the URL parsing against the urls here: https://mathiasbynens.be/demo/url-regex."""

from hypothesis import given
from hypothesis.provisional import domains, urls

from ioc_finder import find_iocs


@given(urls())
def test_url_parsing(url):
    iocs = find_iocs(url)
    try:
        assert len(iocs['urls']) == 1
        assert iocs['urls'][0] == url
    except AssertionError as e:
        print('Failed on url: {}'.format(url))


@given(domains())
def test_domain_parsing(domain):
    iocs = find_iocs(domain)
    try:
        assert len(iocs['domains']) == 1
        assert iocs['domains'][0] == domain
    except AssertionError as e:
        print('Failed on domain: {}'.format(domain))


# TODO: implement similar tests for ipvX strings
