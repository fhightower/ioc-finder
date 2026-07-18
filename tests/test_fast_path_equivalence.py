"""Assert the pure-Python fast paths are equivalent to running the pyparsing
grammars over the same candidate spans.

parse_md5s/sha1s/sha256s/sha512s and parse_ipv4_addresses/parse_ipv4_cidrs no
longer run their grammars — the candidate regex (plus a small Python
transform) is the sole validator. The grammars still exist (md5/sha256 are
embedded in the imphash/authentihash grammars, ipv4_address in the URL/email
grammars), so a grammar edit that skips the regexes would silently make the
two disagree. These tests make the "keep them in sync" comments executable:
each compares a fast-path parser against `_scan_candidates` with the same
candidate regex and the corresponding grammar."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ioc_finder import ioc_grammars
from ioc_finder.ioc_finder import (
    _IPV4_CANDIDATE_RE,
    _IPV4_CIDR_CANDIDATE_RE,
    _MD5_CANDIDATE_RE,
    _SHA1_CANDIDATE_RE,
    _SHA256_CANDIDATE_RE,
    _SHA512_CANDIDATE_RE,
    _scan_candidates,
    parse_ipv4_addresses,
    parse_ipv4_cidrs,
    parse_md5s,
    parse_sha1s,
    parse_sha256s,
    parse_sha512s,
)

HASH_CASES = [
    pytest.param(parse_md5s, _MD5_CANDIDATE_RE, ioc_grammars.md5, 32, id="md5"),
    pytest.param(parse_sha1s, _SHA1_CANDIDATE_RE, ioc_grammars.sha1, 40, id="sha1"),
    pytest.param(parse_sha256s, _SHA256_CANDIDATE_RE, ioc_grammars.sha256, 64, id="sha256"),
    pytest.param(parse_sha512s, _SHA512_CANDIDATE_RE, ioc_grammars.sha512, 128, id="sha512"),
]

# Characters chosen to probe the boundary rules: hex in both cases, the
# 'x'/'X' prefix carve-out (issue #41), non-hex alphanumerics, separators,
# and non-ASCII digits (which `\b`-style boundaries treat as word chars).
BOUNDARY_ALPHABET = "0123456789abcdefABCDEFxXgG._-:/ \n٣١２१"


@pytest.mark.parametrize("parser, candidate_re, grammar, length", HASH_CASES)
def test_hash_fast_path_matches_grammar_on_boundary_cases(parser, candidate_re, grammar, length):
    h = "aB3" * length  # long mixed-case hex pool to slice from
    cases = [
        h[:length],
        f"x{h[:length]}",
        f"X{h[:length]}",
        f"g{h[:length]}",  # non-x letter prefix: rejected by both
        f"{h[:length]}g",
        h[: length - 1],  # one short: no match
        h[: length + 1],  # one long: no match
        f"a {h[:length]} b {h[:length].upper()}",  # dedup on downcased value
        f"٣{h[:length]}",  # non-ASCII digit hugging the run
        f"{h[:length]}٣",
        f"-{h[:length]}-",
        f"{h[:length]}.{h[:length]}",
    ]
    for text in cases:
        assert parser(text) == _scan_candidates(text, candidate_re, grammar), text


@pytest.mark.parametrize("parser, candidate_re, grammar, length", HASH_CASES)
@settings(deadline=None)
@given(st.text(alphabet=BOUNDARY_ALPHABET, max_size=200))
def test_hash_fast_path_matches_grammar(parser, candidate_re, grammar, length, text):
    assert parser(text) == _scan_candidates(text, candidate_re, grammar)


IPV4_EXAMPLES = [
    "1.2.3.4",
    "001.002.003.004",
    "999.1.1.1",
    "1.2.3.4.5",
    "٣3.2.3.4",
    "1.2.3.4٣",
    "1.2.3.4/24 010.0.0.0/8 1.2.3.4/99 1.2.3.4/246",
    "net 1.2.3.4/1٣",
]


def _assert_ipv4_equivalence(text):
    assert parse_ipv4_addresses(text) == _scan_candidates(text, _IPV4_CANDIDATE_RE, ioc_grammars.ipv4_address), text
    assert parse_ipv4_cidrs(text) == _scan_candidates(text, _IPV4_CIDR_CANDIDATE_RE, ioc_grammars.ipv4_cidr), text


@pytest.mark.parametrize("text", IPV4_EXAMPLES)
def test_ipv4_fast_path_matches_grammar_on_boundary_cases(text):
    _assert_ipv4_equivalence(text)


@settings(deadline=None)
@given(st.text(alphabet=BOUNDARY_ALPHABET, max_size=200))
def test_ipv4_fast_path_matches_grammar(text):
    _assert_ipv4_equivalence(text)
