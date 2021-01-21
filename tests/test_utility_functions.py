#!/usr/bin/env python3

from ioc_finder.ioc_grammars import hasMultipleConsecutiveSpaces, hasBothOrNeitherAngleBrackets


def test_hasBothOrNeitherAngleBrackets_1():
    assert hasBothOrNeitherAngleBrackets('<>')
    assert hasBothOrNeitherAngleBrackets('<foo>')
    assert hasBothOrNeitherAngleBrackets('< foo >')
    assert hasBothOrNeitherAngleBrackets('foo')

    assert not hasBothOrNeitherAngleBrackets('<')
    assert not hasBothOrNeitherAngleBrackets('<foo')
    assert not hasBothOrNeitherAngleBrackets('foo<')
    assert not hasBothOrNeitherAngleBrackets('<foo<')
    assert not hasBothOrNeitherAngleBrackets('>')
    assert not hasBothOrNeitherAngleBrackets('>foo')
    assert not hasBothOrNeitherAngleBrackets('foo>')
    assert not hasBothOrNeitherAngleBrackets('>foo>')


def test_hasMultipleConsecutiveSpaces_1():
    assert not hasMultipleConsecutiveSpaces('')
    assert not hasMultipleConsecutiveSpaces(' ')
    assert hasMultipleConsecutiveSpaces('  ')
    assert hasMultipleConsecutiveSpaces('   ')
