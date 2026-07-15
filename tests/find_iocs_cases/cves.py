from pytest import param

CVE_DATA = [
    param(
        "cve-2014-1000 cve 2014-1001 cve-1999-1002 CVE 2999-1003 CVE 1928-1004",
        {"cves": ["CVE-2014-1000", "CVE-2014-1001", "CVE-1999-1002", "CVE-2999-1003", "CVE-1928-1004"]},
        {},
        id="cve_1",
    ),
    param(
        # Years whose digits are all 1s and 2s: the old `Word("12") + Word(nums,
        # exact=3)` year grammar was greedy and non-backtracking, so it consumed
        # every leading 1/2 digit and failed on these.
        "CVE-2121-12345 and CVE-2212-0001",
        {"cves": ["CVE-2121-12345", "CVE-2212-0001"]},
        {},
        id="cve_year_of_all_ones_and_twos",
    ),
]
