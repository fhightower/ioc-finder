"""Make sure that the parsing functions for specific functions are imported properly."""

import pytest
from pyparsing import ParseException

from ioc_finder import parse_urls
from ioc_finder.ioc_finder import _parse_url, _remove_url_userinfo, _url_candidate_spans


def test_url_parsing_func():
    results = parse_urls("https://google.com")
    assert results == ["https://google.com"]


def test_url_candidate_spans_skip_markers_inside_expanded_span():
    text = ("a.a/" * 5000) + " https://example.com/path"

    first = text.split()[0]
    second = "https://example.com/path"
    assert list(_url_candidate_spans(text)) == [
        (0, first),
        (len(first) + 1, second),
    ]


def test_parse_url_raises_on_unparseable_input():
    """`_parse_url` falls through all four URL grammars and raises."""
    with pytest.raises(ParseException, match="could not parse URL"):
        _parse_url("not a url at all")


def test_remove_url_userinfo_skips_unparseable_url():
    """A 'URL' that neither complete grammar can parse is skipped and the
    text is returned unchanged."""
    text = "some text"
    assert _remove_url_userinfo(["not a url at all"], text) == text
