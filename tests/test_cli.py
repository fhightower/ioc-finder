#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json

from click.testing import CliRunner

from ioc_finder import ioc_finder


def test_ioc_parsing_cli():
    runner = CliRunner()
    result = runner.invoke(ioc_finder.cli_find_iocs, ["This is just an example.com https://example.org/test/bingo.php"])
    assert result.exit_code == 0
    output = result.output.strip()
    assert 'example.org' in output
    assert 'example.com' in output
    assert 'https://example.org/test/bingo.php' in output


def test_cli_without_domain_from_url_parsing():
    runner = CliRunner()
    result = runner.invoke(
        ioc_finder.cli_find_iocs,
        ["This is just an example.com https://example.org/test/bingo.php", "--no_url_domain_parsing"],
    )
    assert result.exit_code == 0
    print(result.output.strip())
    assert (
        result.output.strip()
        == """{
    "asns": [],
    "bitcoin_addresses": [],
    "complete_email_addresses": [],
    "cves": [],
    "domains": [
        "example.com"
    ],
    "email_addresses": [],
    "google_adsense_publisher_ids": [],
    "google_analytics_tracker_ids": [],
    "ipv4_cidrs": [],
    "ipv4s": [],
    "ipv6s": [],
    "mac_addresses": [],
    "md5s": [],
    "registry_key_paths": [],
    "sha1s": [],
    "sha256s": [],
    "sha512s": [],
    "ssdeeps": [],
    "urls": [
        "https://example.org/test/bingo.php"
    ],
    "xmpp_addresses": []
}"""
    )


def test_cli_parsing_urls_without_scheme():
    runner = CliRunner()
    result = runner.invoke(ioc_finder.cli_find_iocs, ["This is just an example.com example.org/test/bingo.php"])
    assert result.exit_code == 0
    print(result.output.strip())
    json_results = json.loads(result.output.strip())
    assert 'example.com' in json_results['domains']
    assert 'example.org' in json_results['domains']
    assert 'example.org/test/bingo.php' in json_results['urls']


def test_cli_disabling_parsing_urls_without_scheme():
    runner = CliRunner()
    result = runner.invoke(
        ioc_finder.cli_find_iocs,
        ["This is just an example.com example.org/test/bingo.php", "--no_urls_without_schemes"],
    )
    assert result.exit_code == 0
    print(result.output.strip())
    json_results = json.loads(result.output.strip())
    assert 'example.com' in json_results['domains']
    assert 'example.org' in json_results['domains']
