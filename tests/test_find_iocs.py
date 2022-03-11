from typing import Dict, List

import pytest

from ioc_finder import find_iocs
from ioc_finder.ioc_finder import IndicatorData, IndicatorDict, IndicatorList

from .find_iocs_cases import ALL_TESTS


@pytest.mark.parametrize("text, results, args", ALL_TESTS)
def test_find_iocs(text: str, results: Dict, args: Dict) -> None:
    # Parse input
    iocs = find_iocs(text, **args)

    # Get all keys
    ioc_finder_keys = _get_nonempty_keys(iocs)
    results_keys = _get_nonempty_keys(results)

    # Test output with expected results
    assert sorted(ioc_finder_keys) == sorted(
        results_keys
    ), f"Key values don't match '{ioc_finder_keys}' vs '{results_keys}'"
    for key in results.keys():
        # Compare lists
        if isinstance(iocs[key], list):
            _compare_lists(iocs[key], results[key])  # type: ignore
        # Compare sub dictionaries like for attack patterns
        elif isinstance(iocs[key], dict):
            _compare_dicts(iocs[key], results[key])  # type: ignore


def _compare_lists(ioc_list: IndicatorList, result_list: IndicatorList) -> None:
    assert sorted(ioc_list) == sorted(
        result_list
    ), f"Expected result '{result_list}' did not match parsed IOCs '{ioc_list}'"


def _compare_dicts(ioc_dict: IndicatorDict, result_dict: IndicatorDict) -> None:
    for key in result_dict.keys():
        assert key in result_dict, f"Expected key '{key}' not found in {result_dict.keys()}"
        _compare_lists(ioc_dict[key], result_dict[key])


def _get_nonempty_keys(input: IndicatorData) -> List[str]:
    result = []
    for key, item in input.items():
        # If item is an empty list
        if len(item) == 0:
            continue

        # if item is dict
        if type(item) == dict:
            result += _get_nonempty_keys(item)
        else:
            result.append(key)

    return result
