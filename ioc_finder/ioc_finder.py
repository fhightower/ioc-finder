"""Python package for finding observables in text."""

import json
import re
import urllib.parse as urlparse
from collections.abc import Callable, Iterable, Mapping

import click
import ioc_fanger
from pyparsing import ParseException, ParseResults

from ioc_finder import ioc_grammars

# Cheap regexes used to locate ATT&CK-ID-shaped candidate spans so the
# pyparsing grammars (which carry alternations of hundreds of literal IDs)
# only run where a match could plausibly occur rather than at every offset.
# The leading lookbehind mirrors ioc_grammars.alphanum_word_start, which only
# treats ASCII alphanumerics as word chars. Trailing char classes greedily
# consume any remaining alphanumerics (and dots, for techniques with
# sub-technique suffixes) so the grammar is handed the full token and can
# apply its own word-end check — e.g. "T1156.0012" must reach the grammar
# intact so it can be correctly rejected rather than truncated to "T1156".
_ATTACK_MITIGATION_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])M\d{4}[A-Za-z0-9]*", re.IGNORECASE)
_ATTACK_TACTIC_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])TA\d{4}[A-Za-z0-9]*", re.IGNORECASE)
_ATTACK_TECHNIQUE_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])T\d{4}[A-Za-z0-9.]*", re.IGNORECASE)

# A dotted run of label-like chars — cheap regex used to locate candidate domain
# spans so the pyparsing grammar only runs where a domain could plausibly exist,
# rather than at every offset of the input. The char classes here are kept in
# sync with ioc_grammars.label (ASCII-only); if IDN support is ever added, both
# this regex and the grammar need to change together.
_DOMAIN_CANDIDATE_RE = re.compile(
    # Boundaries mirror ioc_grammars.alphanum_word_start / alphanum_word_end,
    # which only treat ASCII alphanumerics as word chars — so a domain may
    # start right after '-' or '_' (e.g. "(-example.com)", "abc.-def.com").
    r"(?<![A-Za-z0-9])"
    r"[A-Za-z0-9_][A-Za-z0-9_-]*"
    r"(?:\.[A-Za-z0-9_][A-Za-z0-9_-]*)+"
    r"(?![A-Za-z0-9])"
)

# Cheap candidate-span regexes used to anchor the more expensive pyparsing
# grammars on plausible matches, mirroring the _DOMAIN_CANDIDATE_RE pattern.
# Each is intentionally a superset of what its grammar accepts — pyparsing
# applies the precise rules; the regex only narrows where pyparsing runs.

# Local-part character class for complete_email_local_part (alphanums + the
# special chars listed in ioc_grammars + '"' for quoted locals + '()' for
# email comments). The leading "\\@|" alternative mirrors the grammar's
# CaselessLiteral("\\@") branch so a backslash-escaped at-sign inside a local
# part doesn't terminate the candidate prematurely (see "Abc\@def@example.com"
# in test_edge_cases). The tail accepts a domain-shaped run or a bracketed
# IP literal ("[192.168.0.1]", "[IPv6:...]").
_EMAIL_CANDIDATE_RE = re.compile(
    r"(?:\\@|[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~.\"()\\])+"
    r"@"
    r"(?:\[[^\]\s]{1,80}\]|[A-Za-z0-9.\-]+)"
)

# IPv6 candidates: hex+colon runs that contain at least two colons. Boundaries
# mirror ipv6_word_start / ipv6_word_end (alphanums + ':' as word chars). Every
# valid IPv6 has >=2 colons (full form has 7; shortened requires '::'), so this
# excludes plain hex blobs (md5/sha1/sha256, hex bytes) that previously got fed
# to the grammar only to fail there. The grammar still validates the full
# structure, valid hexadectet count, and '::' shortening rules.
_IPV6_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9:])(?:[0-9A-Fa-f]*:){2,}[0-9A-Fa-f]*(?![A-Za-z0-9:])")

# IPv4 candidates: four 1–3 digit groups separated by dots. The lookbehind
# mirrors alphanum_word_start + WordStart("." + nums) — neither alphanumeric
# nor '.' may precede. The trailing `(?!\.\S)` mirrors NotAny(r"\.\S") so a
# fifth dotted segment ("1.2.3.4.5") is excluded; the grammar's per-octet
# `<256` check still runs and rejects e.g. "999.1.1.1".
_IPV4_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9])(?!\.\S)")

# Hash candidates: a hex run of exactly 32/40/64 chars. The leading lookbehind
# mirrors file_hash_word_start (word_chars = alphanums minus 'x'/'X'), so a
# leading 'x'/'X' prefix is allowed (issue #41). The trailing lookahead mirrors
# alphanum_word_end so a longer hex run isn't sliced into a shorter hash —
# e.g. a 64-char run won't surface as an MD5 candidate.
_MD5_CANDIDATE_RE = re.compile(r"(?<![A-WYZa-wyz0-9])[A-Fa-f0-9]{32}(?![A-Za-z0-9])")
_SHA1_CANDIDATE_RE = re.compile(r"(?<![A-WYZa-wyz0-9])[A-Fa-f0-9]{40}(?![A-Za-z0-9])")
_SHA256_CANDIDATE_RE = re.compile(r"(?<![A-WYZa-wyz0-9])[A-Fa-f0-9]{64}(?![A-Za-z0-9])")

# CVE candidates: "CVE" + dash/space separators + 4-digit year (1xxx/2xxx) + dashes
# + 4-or-more digit id. Mirrors `year = Word("12") + Word(nums, exact=3)` and the
# trailing `Word(nums, min=4)` + alphanum_word_end. Case-insensitive to match
# CaselessLiteral("cve").
_CVE_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9])cve[- ]+[12]\d{3}-+\d{4,}(?![A-Za-z0-9])",
    re.IGNORECASE,
)

# imphash / authentihash candidates: the literal keyword (case-insensitive),
# any run of non-alphanumeric separator chars (matching the grammar's
# Optional(Word(printables, excludeChars=alphanums))), then the hash.
# The trailing lookahead mirrors the grammar's alphanum_word_end so we don't
# slice a 32/64-char window out of a longer hex run.
_IMPHASH_CANDIDATE_RE = re.compile(r"(?:imphash|import hash)[^a-z0-9]*[a-f0-9]{32}(?![a-f0-9])")
_AUTHENTIHASH_CANDIDATE_RE = re.compile(r"authentihash[^a-z0-9]*[a-f0-9]{64}(?![a-f0-9])")

# URL candidates: a non-whitespace run that contains either '://' (scheme
# present) or '.<tld>/' (scheme-less URL with a path). The candidate is
# intentionally generous on both ends — the URL grammar and _clean_url
# trim the actual boundaries, so trailing punctuation like ')' or ',' must
# stay in the span. Any non-whitespace char is allowed in the surrounding
# context because the grammar handles unmatched quotes/parens itself and
# _clean_url strips them after the fact.
_URL_CANDIDATE_RE = re.compile(
    r"\S*"
    r"(?:://|\.[A-Za-z][A-Za-z0-9-]*/)"
    r"\S*"
)

# MAC candidates: the three notations the grammar accepts —
# `xx[:-]xx[:-]xx[:-]xx[:-]xx[:-]xx` (mixed colon/dash separators allowed)
# and `xxxx.xxxx.xxxx`. Boundaries mirror mac_address_word_start /
# mac_address_word_end (wordChars = alphanums + ":-.").
_MAC_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9:.\-])"
    r"(?:"
    r"[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5}"
    r"|"
    r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}"
    r")"
    r"(?![A-Za-z0-9:.\-])"
)

# User-agent candidates: the grammar requires the string to start with
# `[Mm]ozilla/<version>`. We anchor on that prefix and take the run up to
# the next Mozilla start (or end of input) so the grammar can split a line
# containing two concatenated user agents into two matches.
_USER_AGENT_START_RE = re.compile(r"[Mm]ozilla/\d")

# File-path candidates: the file_path grammar accepts either a Windows path
# (drive letter + ':' + dotless body + '.' + 1–5 letter extension) or a Unix
# path (starting '~' or '/', same body+extension shape, with a "//" not in
# tokens[0] post-condition the grammar enforces). The body uses
# Word(printables + ' ', exclude_chars='.') — printable chars including
# spaces but no dots — so the regex mirrors that with `[^\s.]+(?:\s[^\s.]+)*`,
# matching dotless tokens that may be separated by single whitespace runs
# (the file_path_1 test case has "AppData \Local" — a space inside a path).
_FILE_PATH_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:"
    r"[A-Za-z0-9]:[^\s.]+(?:\s[^\s.]+)*\.[A-Za-z]{1,5}"
    r"|"
    r"[~/][^\s.]+(?:\s[^\s.]+)*\.[A-Za-z]{1,5}"
    r")"
    r"(?![A-Za-z0-9])"
)

IndicatorList = list[str]
IndicatorDict = dict[str, IndicatorList]
# using `Mapping` b/c it is covariant (https://mypy.readthedocs.io/en/stable/generics.html#variance-of-generic-types)
IndicatorData = Mapping[str, IndicatorList | IndicatorDict]

SUPPORTED_IOC_TYPES = [
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
    "urls_complete",
    "user_agents",
    "xmpp_addresses",
]

DEFAULT_IOC_TYPES = [
    "cves",
    "domains",
    "email_addresses",
    "ipv4s",
    "ipv6s",
    "md5s",
    "sha1s",
    "sha256s",
    "urls",
]


def _deduplicate(indicator_list: Iterable) -> list:
    """Deduplicate the list of observables."""
    return list(set(indicator_list))


def _listify(indicator_list: ParseResults) -> list:
    """Convert the multi-dimensional list into a one-dimensional list with empty entries and duplicates removed."""
    return _deduplicate([indicator[0] for indicator in indicator_list if indicator[0]])


def _remove_items(items: list[str], text: str) -> str:
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
    url = url.removesuffix("'/>")
    url = url.removesuffix('"/>')

    return url


def parse_urls(text: str, *, parse_urls_without_scheme: bool = True) -> list:
    """."""
    grammar = ioc_grammars.scheme_less_url if parse_urls_without_scheme else ioc_grammars.url
    raw_urls = _scan_candidates(text, _URL_CANDIDATE_RE, grammar)
    # Cleaning may collapse two raw matches to the same string, so dedupe again.
    return _deduplicate(map(_clean_url, raw_urls))


def parse_urls_complete(text: str, *, parse_urls_without_scheme: bool = True) -> list:
    """."""
    grammar = ioc_grammars.scheme_less_url_complete if parse_urls_without_scheme else ioc_grammars.url_complete
    raw_urls = _scan_candidates(text, _URL_CANDIDATE_RE, grammar)
    return _deduplicate(map(_clean_url, raw_urls))


def _parse_url(url: str) -> ParseResults:
    """Parse a URL using the narrower grammar first, then the complete grammar."""
    try:
        return ioc_grammars.scheme_less_url.parse_string(url)
    except ParseException:
        return ioc_grammars.scheme_less_url_complete.parse_string(url)


def _remove_url_domain_name(urls: list, text: str) -> str:
    """Remove the domain name of each url from the text."""
    for url in urls:
        parsed_url = _parse_url(url)
        url_authority = parsed_url.url_authority
        if isinstance(url_authority, ParseResults):
            url_authority = url_authority[0]
        text = text.replace(url_authority, " ")
    return text


def _remove_url_paths(urls: list, text: str) -> str:
    """Remove the path of each url from the text."""
    for url in urls:
        parsed_url = _parse_url(url)
        url_path = urlparse.unquote_plus(parsed_url.url_path)

        is_cidr_range = parse_ipv4_cidrs(str(url))
        # if the 'url' has a URL path and is not a cidr range, remove the url_path
        if not is_cidr_range and len(url_path) > 1:
            text = text.replace(url_path, " ")
    return text


def _remove_url_userinfo(urls: list, text: str) -> str:
    """Remove userinfo from each URL so it is not parsed as an email address."""
    for url in urls:
        parsed_url = ioc_grammars.scheme_less_url_complete.parse_string(url)
        userinfo = parsed_url.url_authority.get("url_userinfo")
        if userinfo:
            text = text.replace(f"{userinfo}@", " ")
    return text


def _percent_decode_url(urls: list, text: str) -> str:
    for url in urls:
        text = text.replace(url, urlparse.unquote_plus(url))
    return text


def parse_domain_names(text):
    """."""
    return _scan_candidates(text, _DOMAIN_CANDIDATE_RE, ioc_grammars.domain_name)


def parse_ipv4_addresses(text):
    """."""
    return _scan_candidates(text, _IPV4_CANDIDATE_RE, ioc_grammars.ipv4_address)


def _scan_candidates(text, candidate_re, grammar):
    """Run `grammar.scan_string` only on the spans matched by `candidate_re`,
    deduplicating tokens[0] across spans. Used by hotspot helpers where the
    pyparsing grammar would otherwise be tried at every offset of the input."""
    seen: set[str] = set()
    out: list[str] = []
    for m in candidate_re.finditer(text):
        for tokens, _start, _end in grammar.scan_string(m.group(0)):
            value = tokens[0]
            if value and value not in seen:
                seen.add(value)
                out.append(value)
    return out


_IPV6_HEXNUMS = frozenset("0123456789abcdefABCDEF")


def _is_valid_ipv6(s: str) -> bool:
    """Mirror ioc_grammars.ipv6_address structural validation in pure Python.
    The grammar does no transformation (no parse actions on hexadectet / Combine),
    so replacing the pyparsing call with this validator is behavior-preserving.
    The candidate regex already enforces ipv6_word_start/end, so boundary checks
    aren't repeated here."""
    if s.count(":") < 2:
        return False
    halves = s.split("::")
    if len(halves) > 2:
        return False
    if len(halves) == 2:
        left, right = halves
        left_groups = left.split(":") if left else []
        right_groups = right.split(":") if right else []
        groups = left_groups + right_groups
        if len(groups) > 7:
            return False
    else:
        groups = s.split(":")
        if len(groups) != 8:
            return False
    for g in groups:
        if not (1 <= len(g) <= 4):
            return False
        if not all(c in _IPV6_HEXNUMS for c in g):
            return False
    return True


def parse_ipv6_addresses(text):
    """."""
    seen: set[str] = set()
    out: list[str] = []
    for m in _IPV6_CANDIDATE_RE.finditer(text):
        span = m.group(0)
        if span in seen:
            continue
        if _is_valid_ipv6(span):
            seen.add(span)
            out.append(span)
    return out


def parse_complete_email_addresses(text: str) -> list:
    """."""
    return _scan_candidates(text, _EMAIL_CANDIDATE_RE, ioc_grammars.complete_email_address)


def parse_email_addresses(text: str) -> list:
    """."""
    return _scan_candidates(text, _EMAIL_CANDIDATE_RE, ioc_grammars.email_address)


# there is a trailing underscore on this function to differentiate it from the argument with the same name
def parse_imphashes_(text: str) -> list:
    """."""
    full_imphash_instances = _scan_candidates(text.lower(), _IMPHASH_CANDIDATE_RE, ioc_grammars.imphash)

    return [ioc_grammars.imphash.parse_string(imphash).hash[0] for imphash in full_imphash_instances]


# there is a trailing underscore on this function to differentiate it from the argument with the same name
def parse_authentihashes_(text: str) -> list:
    """."""
    full_authentihash_instances = _scan_candidates(text.lower(), _AUTHENTIHASH_CANDIDATE_RE, ioc_grammars.authentihash)

    return [ioc_grammars.authentihash.parse_string(a).hash[0] for a in full_authentihash_instances]


def parse_md5s(text):
    """."""
    return _scan_candidates(text, _MD5_CANDIDATE_RE, ioc_grammars.md5)


def parse_sha1s(text):
    """."""
    return _scan_candidates(text, _SHA1_CANDIDATE_RE, ioc_grammars.sha1)


def parse_sha256s(text):
    """."""
    return _scan_candidates(text, _SHA256_CANDIDATE_RE, ioc_grammars.sha256)


def parse_sha512s(text):
    """."""
    sha512s = ioc_grammars.sha512.search_string(text)
    return _listify(sha512s)


def parse_ssdeeps(text):
    """."""
    ssdeeps = ioc_grammars.ssdeep.search_string(text)
    return _listify(ssdeeps)


def parse_asns(text):
    """."""
    asns = ioc_grammars.asn.search_string(text)
    return _listify(asns)


def parse_cves(text):
    """."""
    return _scan_candidates(text, _CVE_CANDIDATE_RE, ioc_grammars.cve)


def parse_ipv4_cidrs(text: str) -> list:
    """."""
    cidrs = ioc_grammars.ipv4_cidr.search_string(text)
    return _listify(cidrs)


def parse_registry_key_paths(text):
    """."""
    parsed_registry_key_paths = ioc_grammars.registry_key_path.search_string(text)
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
    adsense_publisher_ids = ioc_grammars.google_adsense_publisher_id.search_string(text)
    return _listify(adsense_publisher_ids)


def parse_google_analytics_ids(text):
    """."""
    analytics_tracker_ids = ioc_grammars.google_analytics_tracker_id.search_string(text)
    return _listify(analytics_tracker_ids)


def parse_bitcoin_addresses(text):
    """."""
    bitcoin_addresses = ioc_grammars.bitcoin_address.search_string(text)
    return _listify(bitcoin_addresses)


def parse_monero_addresses(text):
    """."""
    monero_addresses = ioc_grammars.monero_address.search_string(text)
    return _listify(monero_addresses)


def parse_xmpp_addresses(text: str) -> list:
    """."""
    xmpp_addresses = ioc_grammars.xmpp_address.search_string(text)
    return _listify(xmpp_addresses)


def _remove_xmpp_local_part(xmpp_addresses: list, text: str) -> str:
    """Remove the local part of each xmpp_address from the text."""
    for address in xmpp_addresses:
        text = text.replace(address.split("@")[0] + "@", " ")

    return text


def parse_mac_addresses(text):
    """."""
    return _scan_candidates(text, _MAC_CANDIDATE_RE, ioc_grammars.mac_address)


def parse_user_agents(text):
    """."""
    # User-agent strings can contain almost any printable char, so we can't
    # build a candidate regex that captures the whole UA up front. Instead,
    # find each `[Mm]ozilla/<digit>` start and run the grammar on the slice
    # from that start to the next start (or end of text). That keeps two
    # concatenated UAs on the same line as separate spans, which the grammar
    # otherwise has trouble splitting because Combine(...adjacent=False) will
    # happily merge them.
    starts = [m.start() for m in _USER_AGENT_START_RE.finditer(text)]
    if not starts:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(text)
        for tokens, _s, _e in ioc_grammars.user_agent.scan_string(text[start:end]):
            value = tokens[0]
            if value and value not in seen:
                seen.add(value)
                out.append(value)
    return out


def parse_file_paths(text):
    """."""
    return _scan_candidates(text, _FILE_PATH_CANDIDATE_RE, ioc_grammars.file_path)


def parse_pre_attack_tactics(text):
    """."""
    return _scan_candidates(text, _ATTACK_TACTIC_CANDIDATE_RE, ioc_grammars.pre_attack_tactics_grammar)


def parse_pre_attack_techniques(text):
    """."""
    return _scan_candidates(text, _ATTACK_TECHNIQUE_CANDIDATE_RE, ioc_grammars.pre_attack_techniques_grammar)


def parse_enterprise_attack_mitigations(text):
    """."""
    return _scan_candidates(text, _ATTACK_MITIGATION_CANDIDATE_RE, ioc_grammars.enterprise_attack_mitigations_grammar)


def parse_enterprise_attack_tactics(text):
    """."""
    return _scan_candidates(text, _ATTACK_TACTIC_CANDIDATE_RE, ioc_grammars.enterprise_attack_tactics_grammar)


def parse_enterprise_attack_techniques(text):
    """."""
    return _scan_candidates(text, _ATTACK_TECHNIQUE_CANDIDATE_RE, ioc_grammars.enterprise_attack_techniques_grammar)


def parse_mobile_attack_mitigations(text):
    """."""
    return _scan_candidates(text, _ATTACK_MITIGATION_CANDIDATE_RE, ioc_grammars.mobile_attack_mitigations_grammar)


def parse_mobile_attack_tactics(text):
    """."""
    return _scan_candidates(text, _ATTACK_TACTIC_CANDIDATE_RE, ioc_grammars.mobile_attack_tactics_grammar)


def parse_mobile_attack_techniques(text):
    """."""
    return _scan_candidates(text, _ATTACK_TECHNIQUE_CANDIDATE_RE, ioc_grammars.mobile_attack_techniques_grammar)


def parse_tlp_labels(text):
    """."""
    tlp_labels = ioc_grammars.tlp_label.search_string(text)
    return _listify(tlp_labels)


@click.command()
@click.argument("text", required=False)
@click.option(
    "--no_url_domain_parsing",
    is_flag=True,
    help="Using this flag will not parse domain names from URLs",
)
@click.option(
    "--no_parse_from_url_path",
    is_flag=True,
    help="Using this flag will not parse observables from URL paths",
)
@click.option(
    "--no_email_addr_domain_parsing",
    is_flag=True,
    help="Using this flag will not parse domain names from email addresses",
)
@click.option(
    "--no_cidr_address_parsing",
    is_flag=True,
    help="Using this flag will not parse IP addresses from CIDR ranges",
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
@click.option(
    "--all",
    "parse_all",
    is_flag=True,
    help="Parse every supported indicator type instead of the common defaults.",
)
def cli_find_iocs(
    text,
    no_url_domain_parsing,
    no_parse_from_url_path,
    no_email_addr_domain_parsing,
    no_cidr_address_parsing,
    no_xmpp_addr_domain_parsing,
    parse_urls_without_scheme,
    parse_all,
):
    """CLI interface for parsing observables."""
    stdin_text = click.get_text_stream("stdin")

    # if there is stdin, use it
    if not text and stdin_text:
        text = "\n".join(stdin_text)
        # text = '\n'.join([line for line in stdin_text])

    included_ioc_types = list(SUPPORTED_IOC_TYPES if parse_all else DEFAULT_IOC_TYPES)
    iocs = find_iocs(
        text,
        parse_domain_from_url=not no_url_domain_parsing,
        parse_from_url_path=not no_parse_from_url_path,
        parse_domain_from_email_address=not no_email_addr_domain_parsing,
        parse_address_from_cidr=not no_cidr_address_parsing,
        parse_domain_name_from_xmpp_address=not no_xmpp_addr_domain_parsing,
        parse_urls_without_scheme=parse_urls_without_scheme,
        included_ioc_types=included_ioc_types,
    )
    ioc_string = json.dumps(iocs, indent=4, sort_keys=True)
    print(ioc_string)


def find_iocs(
    text: str,
    *,
    parse_domain_from_url: bool = True,
    parse_from_url_path: bool = True,
    parse_domain_from_email_address: bool = True,
    parse_address_from_cidr: bool = True,
    parse_domain_name_from_xmpp_address: bool = True,
    parse_urls_without_scheme: bool = True,
    included_ioc_types: Iterable[str] | None = None,
) -> IndicatorData:
    """Find observables (a.k.a. indicators of compromise) in the given text.

    Args:
        text: The text to parse for indicators.
        parse_domain_from_url: Whether to parse domain names from URLs. Only applicable
            when ``"domains"`` is in ``included_ioc_types``.
        parse_from_url_path: Whether to parse observables from URL paths. Only applicable
            when IOC types that could appear in a URL path (e.g. ``"domains"``, hash types)
            are in ``included_ioc_types``.
        parse_domain_from_email_address: Whether to parse domain names from email addresses.
            Only applicable when ``"domains"`` is in ``included_ioc_types``.
        parse_address_from_cidr: Whether to parse IP addresses from CIDR ranges. Only
            applicable when ``"ipv4s"`` is in ``included_ioc_types``.
        parse_domain_name_from_xmpp_address: Whether to parse domain names from XMPP
            addresses. Only applicable when ``"domains"`` is in ``included_ioc_types``.
        parse_urls_without_scheme: Whether to parse URLs without a scheme. Only applicable
            when ``"urls"`` or ``"urls_complete"`` is in ``included_ioc_types``.
        included_ioc_types: Collection of IOC type names to parse. If ``None``,
            the common default types are parsed (see ``DEFAULT_IOC_TYPES``). For
            the full list of parseable types, see ``SUPPORTED_IOC_TYPES``. When
            specified, the boolean options above only take effect if their
            corresponding IOC type is included.
    """
    if included_ioc_types is None:
        included_ioc_types = DEFAULT_IOC_TYPES

    included_ioc_types = set(included_ioc_types)
    iocs = {}

    text = prepare_text(text)
    # keep a copy of the original text - some items should be parsed from the original text
    original_text = text

    # urls
    if "urls" in included_ioc_types:
        iocs["urls"] = parse_urls(text, parse_urls_without_scheme=parse_urls_without_scheme)

    # urls_complete
    if "urls_complete" in included_ioc_types:
        iocs["urls_complete"] = parse_urls_complete(text, parse_urls_without_scheme=parse_urls_without_scheme)

    # TODO: clean this section up
    if not parse_domain_from_url and not parse_from_url_path:
        text = _remove_items(iocs.get("urls", []), text)
        text = _remove_items(iocs.get("urls_complete", []), text)
    elif not parse_domain_from_url:
        text = _percent_decode_url(iocs.get("urls", []), text)
        text = _remove_url_domain_name(iocs.get("urls", []), text)

        text = _percent_decode_url(iocs.get("urls_complete", []), text)
        text = _remove_url_domain_name(iocs.get("urls_complete", []), text)
    elif not parse_from_url_path:
        text = _percent_decode_url(iocs.get("urls", []), text)
        text = _remove_url_paths(iocs.get("urls", []), text)

        text = _percent_decode_url(iocs.get("urls_complete", []), text)
        text = _remove_url_paths(iocs.get("urls_complete", []), text)
    else:
        text = _percent_decode_url(iocs.get("urls", []), text)
        text = _percent_decode_url(iocs.get("urls_complete", []), text)

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

    if "email_addresses_complete" in included_ioc_types or "email_addresses" in included_ioc_types:
        text = _remove_url_userinfo(iocs.get("urls_complete", []), text)

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
    url_parsing_requires_cidr_removal = (
        "urls" in included_ioc_types or "urls_complete" in included_ioc_types
    ) and parse_urls_without_scheme
    ip_address_parsing_requires_cidr_removal = "ipv4s" in included_ioc_types and not parse_address_from_cidr
    if url_parsing_requires_cidr_removal or ip_address_parsing_requires_cidr_removal:
        cidr_ranges = _get_items(iocs, "ipv4_cidrs", parse_ipv4_cidrs, text)
        if url_parsing_requires_cidr_removal:
            for cidr in cidr_ranges:
                if cidr in iocs.get("urls", []):
                    iocs["urls"].remove(cidr)
                if cidr in iocs.get("urls_complete", []):
                    iocs["urls_complete"].remove(cidr)
        if ip_address_parsing_requires_cidr_removal:
            text = _remove_items(cidr_ranges, text)

    # file hashes
    if "imphashes" in included_ioc_types:
        iocs["imphashes"] = parse_imphashes_(text)
    if "md5s" in included_ioc_types:
        # remove the imphashes so they are not also parsed as md5s
        imphashes = _get_items(iocs, "imphashes", parse_imphashes_, text)
        text = _remove_items(imphashes, text)

    if "authentihashes" in included_ioc_types:
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
        # remove ipv6 addresses so they are not parsed as ssdeep hashes
        # (see https://github.com/fhightower/ioc-finder/issues/228)
        ssdeep_text = text
        ipv6s = _get_items(iocs, "ipv6s", parse_ipv6_addresses, text)
        ssdeep_text = _remove_items(ipv6s, ssdeep_text)
        iocs["ssdeeps"] = parse_ssdeeps(ssdeep_text)

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
            urls = _get_items(
                iocs,
                "urls",
                parse_urls,
                text,
                parse_urls_without_scheme=parse_urls_without_scheme,
            )
            text = _remove_url_paths(urls, text)

        iocs["file_paths"] = parse_file_paths(text)

    return iocs
