import pytest

from ioc_finder import find_iocs

from .data import ALL_TESTS


@pytest.mark.parametrize("text,results", ALL_TESTS)
def test_find_iocs(text, results):
    print(text)
    print(results)
    assert 1 == 2
