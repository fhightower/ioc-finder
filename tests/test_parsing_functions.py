"""Make sure that the parsing functions for specific functions are imported properly."""

from ioc_finder import parse_snort_rules, parse_urls, parse_yara_rules
from ioc_finder.ioc_finder import _url_candidate_spans


def test_url_parsing_func():
    results = parse_urls("https://google.com")
    assert results == ["https://google.com"]


def test_url_candidate_spans_skip_markers_inside_expanded_span():
    text = ("a.a/" * 5000) + " https://example.com/path"

    assert list(_url_candidate_spans(text)) == [text.split()[0], "https://example.com/path"]


def test_snort_rule_parsing_func():
    rule = 'alert tcp any any -> any 80 (msg:"x"; sid:1;)'
    assert parse_snort_rules(rule) == [rule]


def test_snort_rule_dedup():
    """Identical rules pasted twice in a document collapse to one match."""
    rule = 'alert tcp any any -> any 80 (msg:"x"; sid:1;)'
    assert parse_snort_rules(rule + "\n" + rule) == [rule]


def test_snort_rule_after_unbalanced_anchor_still_found():
    """An unbalanced/truncated rule must not prevent a real rule that comes
    after it from being detected. The truncated anchor is skipped and the
    search continues from just past its header."""
    text = (
        # Truncated rule — opens a paren but never closes it.
        'alert tcp any any -> any 1 (msg:"truncated"; sid:1;\n'
        # Real rule on the next line.
        'alert tcp any any -> any 2 (msg:"ok"; sid:2;)'
    )
    rules = parse_snort_rules(text)
    assert rules == ['alert tcp any any -> any 2 (msg:"ok"; sid:2;)']


def test_yara_rule_parsing_func():
    rule = "rule TestRule { condition: true }"
    assert parse_yara_rules(rule) == [rule]


def test_yara_rule_with_hex_string_braces():
    """The outer rule's brace counter must include — and then balance —
    the braces that wrap a Yara hex string."""
    rule = "rule HexCheck { strings: $a = { 4D 5A } condition: $a }"
    assert parse_yara_rules(rule) == [rule]


def test_yara_rule_dedup():
    rule = "rule TestRule { condition: true }"
    assert parse_yara_rules(rule + "\n\n" + rule) == [rule]


def test_yara_and_snort_no_match_on_empty_input():
    assert parse_yara_rules("") == []
    assert parse_snort_rules("") == []


def test_snort_rule_with_escaped_quote_in_msg():
    """`\\"` inside a Snort msg must not terminate the quoted span; the
    backslash escape consumes the next char and the parser keeps going to
    the real closing quote."""
    rule = 'alert tcp any any -> any 80 (msg:"a\\"b"; sid:1;)'
    assert parse_snort_rules(rule) == [rule]


def test_yara_rule_escaped_quote_in_string():
    """`\\"` inside a Yara string literal must not terminate the string
    span; the brace counter must reach the real closing `"` before
    treating any subsequent `}` as the rule close."""
    rule = 'rule EscQuote { strings: $a = "a\\"}b" condition: $a }'
    assert parse_yara_rules(rule) == [rule]


def test_yara_rule_escape_in_regex():
    """A `\\/` inside `/regex/` must not be treated as the regex's closing
    delimiter — same escape rule as for double-quoted strings."""
    rule = "rule EscRegex { strings: $a = /a\\/}b/ condition: $a }"
    assert parse_yara_rules(rule) == [rule]


def test_yara_rule_stray_slash_without_close():
    """A `/` with no closing `/` on the same line must be treated as a
    literal slash rather than starting an unterminated regex literal that
    would swallow the rest of the buffer."""
    # The `5/2` looks like a slash but there's no closing `/` on that line —
    # the walker must fall back to literal-slash handling and keep going.
    rule = "rule StraySlash { condition: 5/2 == 2 }"
    assert parse_yara_rules(rule) == [rule]


def test_yara_rule_unbalanced_anchor_skipped():
    """An unclosed `rule X {` must not swallow downstream content; a real
    rule that follows must still be returned."""
    text = (
        "rule Truncated {\n"
        "    condition: true\n"
        # Real rule afterwards.
        "rule Good { condition: true }"
    )
    rules = parse_yara_rules(text)
    assert rules == ["rule Good { condition: true }"]
