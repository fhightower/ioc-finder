from typing import Dict, List

import pytest
from ioc_finder import find_iocs
from .find_iocs_cases import ALL_TESTS


@pytest.mark.parametrize("text,results", ALL_TESTS)
def test_find_iocs(text: str, results):
    # Parse input
    iocs = find_iocs(text)

    # Get all keys
    ioc_finder_keys = _get_nonempty_keys(iocs)
    # results_keys = _get_nonempty_keys(results)
    results_keys = list(results.keys())

    # Test output with expected results
    assert sorted(ioc_finder_keys) == sorted(results_keys)
    for key in ioc_finder_keys:
        # Compare lists
        if type(iocs[key]) == list:
            _compare_lists(iocs[key], results[key])
        # Compare sub dictionaries like for attack patterns
        elif type(iocs[key]) == dict:
            for subkey in iocs[key].keys():
                assert subkey in results[key], f"Expected key '{key}' not found in {results[key]}"
                _compare_lists(iocs[key][subkey], results[key][subkey])


def _compare_lists(ioc_list: List, result_list: List):
    assert sorted(ioc_list) == sorted(result_list), f"Expected result '{result_list}' did not match parsed IOCs '{ioc_list}'"


def _get_nonempty_keys(input: Dict):
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
