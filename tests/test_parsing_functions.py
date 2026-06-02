"""Make sure that the parsing functions for specific functions are imported properly."""

from ioc_finder import parse_urls
from ioc_finder.ioc_finder import _url_candidate_spans


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
