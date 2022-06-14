import json

from click.testing import CliRunner

from ioc_finder import ioc_finder


def test_parse_cli_stdin():
    runner = CliRunner()
    result = runner.invoke(
        ioc_finder.cli_find_iocs, input="This is just an example.com https://example.org/test/bingo.php"
    )
    assert result.exit_code == 0
    output = result.output.strip()
    assert "example.org" in output
    assert "example.com" in output
    assert "https://example.org/test/bingo.php" in output


def test_ioc_parsing_cli():
    runner = CliRunner()
    result = runner.invoke(ioc_finder.cli_find_iocs, ["This is just an example.com https://example.org/test/bingo.php"])
    assert result.exit_code == 0
    output = result.output.strip()
    assert "example.org" in output
    assert "example.com" in output
    assert "https://example.org/test/bingo.php" in output


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
        "example.com"
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
}"""
    )


def test_cli_parsing_urls_without_scheme():
    runner = CliRunner()
    result = runner.invoke(ioc_finder.cli_find_iocs, ["This is just an example.com example.org/test/bingo.php"])
    assert result.exit_code == 0
    print(result.output.strip())
    json_results = json.loads(result.output.strip())
    assert "example.com" in json_results["domains"]
    assert "example.org" in json_results["domains"]
    assert "example.org/test/bingo.php" in json_results["urls"]


def test_cli_disabling_parsing_urls_without_scheme():
    runner = CliRunner()
    result = runner.invoke(
        ioc_finder.cli_find_iocs,
        ["This is just an example.com example.org/test/bingo.php", "--parse_urls_without_scheme"],
    )
    assert result.exit_code == 0
    print(result.output.strip())
    json_results = json.loads(result.output.strip())
    assert "example.com" in json_results["domains"]
    assert "example.org" in json_results["domains"]


def test_cli_disabling_import_hash_parsing():
    runner = CliRunner()
    result = runner.invoke(ioc_finder.cli_find_iocs, ["imphash 18ddf28a71089acdbab5038f58044c0a", "--no_import_hashes"])
    assert result.exit_code == 0
    json_results = json.loads(result.output.strip())
    # even if we don't parse imphashes, they are still removed so they aren't parsed as md5s
    assert json_results["md5s"] == []
    assert not json_results.get("imphashes")

    result = runner.invoke(ioc_finder.cli_find_iocs, ["imphash 18ddf28a71089acdbab5038f58044c0a"])
    assert result.exit_code == 0
    json_results = json.loads(result.output.strip())
    assert json_results["imphashes"] == ["18ddf28a71089acdbab5038f58044c0a"]
