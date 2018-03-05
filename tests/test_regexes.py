#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ioc_finder.ioc_finder import _get_regexes


def test_get_regexes():
    """Make sure the regexes are read properly."""
    regexes = _get_regexes()
    assert len(regexes) == 8
