"""Tests for the library's logging instrumentation."""

import logging

import pytest

import ioc_finder
from ioc_finder import find_iocs
from ioc_finder.ioc_finder import _clean_url, _count_iocs, prepare_text


def test_package_attaches_null_handler():
    """The package must ship a NullHandler so importing it never produces 'no handler' warnings."""
    handlers = logging.getLogger("ioc_finder").handlers
    assert any(isinstance(h, logging.NullHandler) for h in handlers)
    assert ioc_finder is not None  # silence unused-import lint


def test_find_iocs_logs_info_at_entry_and_exit(caplog):
    with caplog.at_level(logging.INFO, logger="ioc_finder.ioc_finder"):
        find_iocs("hello example.com world")
    info_msgs = [r.message for r in caplog.records if r.levelno == logging.INFO]
    assert any("find_iocs starting" in m for m in info_msgs)
    assert any("find_iocs completed" in m for m in info_msgs)


def test_unsupported_ioc_types_emit_warning_and_are_ignored(caplog):
    with caplog.at_level(logging.WARNING, logger="ioc_finder.ioc_finder"):
        result = find_iocs("hi", included_ioc_types=["domains", "not_a_real_type"])
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("not_a_real_type" in r.getMessage() for r in warnings)
    # the unsupported type should not have a key in the result
    assert "not_a_real_type" not in result
    assert "domains" in result


def test_debug_logs_emit_per_type_counts(caplog):
    with caplog.at_level(logging.DEBUG, logger="ioc_finder.ioc_finder"):
        find_iocs("see example.com")
    debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
    assert any("result counts" in m for m in debug_msgs)


def test_prepare_text_logs_when_fanging_changes_input(caplog):
    with caplog.at_level(logging.DEBUG, logger="ioc_finder.ioc_finder"):
        prepare_text("visit example[.]com")  # bracket-fang triggers a real change
    debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
    assert any("fanged the input" in m for m in debug_msgs)


def test_prepare_text_does_not_log_when_no_change(caplog):
    with caplog.at_level(logging.DEBUG, logger="ioc_finder.ioc_finder"):
        prepare_text("nothing to fang here")
    debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
    assert not any("fanged the input" in m for m in debug_msgs)


def test_clean_url_logs_when_trimming(caplog):
    with caplog.at_level(logging.DEBUG, logger="ioc_finder.ioc_finder"):
        result = _clean_url('https://example.com/path"')
    assert result == "https://example.com/path"
    debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
    assert any("_clean_url trimmed" in m for m in debug_msgs)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (["a", "b", "c"], 3),
        ([], 0),
        ({"enterprise": ["a"], "mobile": ["b", "c"]}, 3),
        ({}, 0),
    ],
)
def test_count_iocs(value, expected):
    assert _count_iocs(value) == expected
