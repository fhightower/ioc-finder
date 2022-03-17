from typing import Dict

import pytest

from ioc_finder import find_iocs
from ioc_finder.ioc_finder import IndicatorDict, IndicatorList

from .find_iocs_cases import ALL_TESTS


@pytest.mark.parametrize("text, results, args", ALL_TESTS)
def test_find_iocs(text: str, results: Dict, args: Dict) -> None:
    # Parse input
    iocs = find_iocs(text, **args)

    for key, value in iocs.items():
        # Compare lists
        if isinstance(value, list):
            _compare_lists(key, value, results.get(key, []))
        # Compare sub dictionaries like for attack patterns
        elif isinstance(value, dict):
            _compare_dicts(key, value, results.get(key, {}))


def _compare_lists(key_name: str, ioc_list: IndicatorList, result_list: IndicatorList) -> None:
    assert sorted(ioc_list) == sorted(
        result_list
    ), f"Unexpected result for key '[{key_name}]' -> Expected: '{result_list}' Received: '{ioc_list}'"


def _compare_dicts(key_name: str, ioc_dict: IndicatorDict, result_dict: IndicatorDict) -> None:
    for ioc_key, ioc_value in ioc_dict.items():
        if isinstance(ioc_value, list):
            _compare_lists(f"{key_name},{ioc_key}", ioc_value, result_dict.get(ioc_key, []))
