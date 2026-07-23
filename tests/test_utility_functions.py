#!/usr/bin/env python3

from ioc_finder.ioc_grammars import hasBothOrNeitherAngleBrackets, hasMultipleConsecutiveSpaces


def test_hasBothOrNeitherAngleBrackets_1():
    assert hasBothOrNeitherAngleBrackets("<>")
    assert hasBothOrNeitherAngleBrackets("<foo>")
    assert hasBothOrNeitherAngleBrackets("< foo >")
    assert hasBothOrNeitherAngleBrackets("foo")

    assert not hasBothOrNeitherAngleBrackets("<")
    assert not hasBothOrNeitherAngleBrackets("<foo")
    assert not hasBothOrNeitherAngleBrackets("foo<")
    assert not hasBothOrNeitherAngleBrackets("<foo<")
    assert not hasBothOrNeitherAngleBrackets(">")
    assert not hasBothOrNeitherAngleBrackets(">foo")
    assert not hasBothOrNeitherAngleBrackets("foo>")
    assert not hasBothOrNeitherAngleBrackets(">foo>")


def test_hasMultipleConsecutiveSpaces_1():
    assert not hasMultipleConsecutiveSpaces("")
    assert not hasMultipleConsecutiveSpaces(" ")
    assert hasMultipleConsecutiveSpaces("  ")
    assert hasMultipleConsecutiveSpaces("   ")

    # Runs of spaces anywhere in the string count, not only at its start.
    assert hasMultipleConsecutiveSpaces("a  b")
    assert hasMultipleConsecutiveSpaces("a b  c")
    assert hasMultipleConsecutiveSpaces("Foo.exe  trailing junk")
    assert not hasMultipleConsecutiveSpaces("a b c")
