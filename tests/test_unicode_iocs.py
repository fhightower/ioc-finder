"""Tests for the ``parse_unicode_iocs`` option (https://github.com/fhightower/ioc-finder/issues/298)."""

from ioc_finder import find_iocs
from ioc_finder.ioc_finder import (
    parse_complete_email_addresses,
    parse_domain_names,
    parse_email_addresses,
    parse_urls,
    parse_xmpp_addresses,
)

# `ı` is U+0131 LATIN SMALL LETTER DOTLESS I — the character from the issue.
UNICODE_DOMAIN = "warrıors.com"


def test_unicode_domain_not_parsed_by_default():
    # Without the option, a Unicode label is not recognised: the ASCII candidate
    # regex starts the domain after the non-ASCII char, so only the ASCII tail
    # surfaces (pre-existing behaviour, kept for backwards compatibility —
    # see https://github.com/fhightower/ioc-finder/issues/298).
    assert find_iocs("warrıors[dot]com")["domains"] == ["ors.com"]
    assert parse_domain_names("warrıors.com") == ["ors.com"]


def test_unicode_domain_parsed_when_opted_in():
    assert find_iocs("warrıors[dot]com", parse_unicode_iocs=True)["domains"] == [UNICODE_DOMAIN]
    assert find_iocs(f"see {UNICODE_DOMAIN} for details", parse_unicode_iocs=True)["domains"] == [UNICODE_DOMAIN]
    assert parse_domain_names(f"a {UNICODE_DOMAIN} b", parse_unicode_iocs=True) == [UNICODE_DOMAIN]


def test_unicode_domain_across_scripts():
    for domain in ("exämple.com", "пример.com", "δοκιμή.com", "中文.com"):
        assert parse_domain_names(f"go to {domain} now", parse_unicode_iocs=True) == [domain]


def test_unicode_domain_picks_rightmost_tld():
    # Same right-to-left TLD walk as the ASCII path.
    assert parse_domain_names("föö.com.invalid", parse_unicode_iocs=True) == ["föö.com"]


def test_unicode_boundary_semantics():
    """In Unicode mode, a non-ASCII letter is a word character: `example.com中`
    is one word (no domain), the same way `example.comX` is one word in ASCII
    mode. ASCII mode instead treats the `中` as a boundary and reports
    `example.com`. Deliberate semantic difference — see the comment on
    `_DOMAIN_CANDIDATE_RE_UNICODE`."""
    assert parse_domain_names("see example.com中 now") == ["example.com"]
    assert parse_domain_names("see example.com中 now", parse_unicode_iocs=True) == []

    # Scope: the rule applies to bare domains only. Email/URL/XMPP grammars
    # keep ASCII word boundaries even in the Unicode layer, so Unicode mode
    # never removes an email/URL/XMPP match that ASCII mode finds.
    assert parse_email_addresses("bob@example.com中") == ["bob@example.com"]
    assert parse_email_addresses("bob@example.com中", parse_unicode_iocs=True) == ["bob@example.com"]
    assert parse_urls("https://example.com中/path", parse_unicode_iocs=True) == ["https://example.com"]
    assert parse_xmpp_addresses("a@jabber.example.com中", parse_unicode_iocs=True) == ["a@jabber.example.com"]


def test_unicode_email_address():
    text = f"reach out to bob@{UNICODE_DOMAIN} please"
    assert parse_email_addresses(text, parse_unicode_iocs=True) == [f"bob@{UNICODE_DOMAIN}"]
    assert parse_complete_email_addresses(text, parse_unicode_iocs=True) == [f"bob@{UNICODE_DOMAIN}"]

    iocs = find_iocs(text, parse_unicode_iocs=True, included_ioc_types=["email_addresses", "domains"])
    assert iocs["email_addresses"] == [f"bob@{UNICODE_DOMAIN}"]
    assert iocs["domains"] == [UNICODE_DOMAIN]


def test_unicode_email_not_parsed_by_default():
    text = f"bob@{UNICODE_DOMAIN}"
    assert parse_email_addresses(text) == []


def test_unicode_url():
    text = f"visit https://{UNICODE_DOMAIN}/path?q=1#frag now"
    assert parse_urls(text, parse_unicode_iocs=True) == [f"https://{UNICODE_DOMAIN}/path?q=1#frag"]

    # The domain is also pulled out of the URL.
    iocs = find_iocs(text, parse_unicode_iocs=True, included_ioc_types=["urls", "domains"])
    assert iocs["urls"] == [f"https://{UNICODE_DOMAIN}/path?q=1#frag"]
    assert iocs["domains"] == [UNICODE_DOMAIN]


def test_unicode_url_without_scheme():
    text = f"{UNICODE_DOMAIN}/some/path"
    assert parse_urls(text, parse_unicode_iocs=True) == [text]


def test_unicode_scheme_ful_url_not_double_counted():
    """The two-pass URL scan (scheme-ful first, then masked scheme-less — see
    issue #244) must also hold in Unicode mode: one URL in, one URL out."""
    text = f"hit https://{UNICODE_DOMAIN}/path today"
    assert parse_urls(text, parse_unicode_iocs=True) == [f"https://{UNICODE_DOMAIN}/path"]


def test_unicode_url_domain_not_double_counted_as_email():
    # `_remove_url_userinfo` has to be able to re-parse a Unicode URL.
    text = f"http://user@{UNICODE_DOMAIN}/x"
    iocs = find_iocs(text, parse_unicode_iocs=True, included_ioc_types=["urls_complete", "email_addresses"])
    assert iocs["urls_complete"] == [f"http://user@{UNICODE_DOMAIN}/x"]
    assert iocs["email_addresses"] == []


def test_unicode_url_domain_removal_branch():
    """`parse_domain_from_url=False` exercises `_remove_url_domain_name` →
    `_parse_url`, which must re-parse a Unicode URL with the Unicode grammars."""
    text = f"see https://{UNICODE_DOMAIN}/path now"
    iocs = find_iocs(
        text,
        parse_unicode_iocs=True,
        parse_domain_from_url=False,
        included_ioc_types=["urls", "domains"],
    )
    assert iocs["urls"] == [f"https://{UNICODE_DOMAIN}/path"]
    assert iocs["domains"] == []


def test_unicode_xmpp_address():
    text = f"alice@jabber.{UNICODE_DOMAIN}"
    assert parse_xmpp_addresses(text, parse_unicode_iocs=True) == [text]
    iocs = find_iocs(text, parse_unicode_iocs=True, included_ioc_types=["xmpp_addresses"])
    assert iocs["xmpp_addresses"] == [text]


def test_unicode_option_does_not_affect_ascii_results():
    text = "Email bob@example.com about https://example.org/foo and 1.2.3.4 (cve-2020-1234)."
    assert find_iocs(text) == find_iocs(text, parse_unicode_iocs=True)


def test_tld_stays_ascii():
    # IDN TLDs live in the IANA list in punycode form, so a non-ASCII string in
    # the TLD position is not a domain even with the option enabled.
    assert parse_domain_names("example.cöm", parse_unicode_iocs=True) == []


def test_cli_unicode_flag():
    import json

    from click.testing import CliRunner

    from ioc_finder.ioc_finder import cli_find_iocs

    runner = CliRunner()
    result = runner.invoke(cli_find_iocs, ["--parse_unicode_iocs", f"go to {UNICODE_DOMAIN}"])
    assert result.exit_code == 0
    assert json.loads(result.output)["domains"] == [UNICODE_DOMAIN]

    # Without the flag the Unicode label is not recognised.
    result = runner.invoke(cli_find_iocs, [f"go to {UNICODE_DOMAIN}"])
    assert result.exit_code == 0
    assert json.loads(result.output)["domains"] == ["ors.com"]
