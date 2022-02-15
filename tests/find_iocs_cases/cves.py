def case_cve_simple():
    text = "cve-2014-1000 cve 2014-1001 cve-1999-1002 CVE 2999-1003 CVE 1928-1004"
    results = {"cves": [
        "CVE-2014-1000",
        "CVE-2014-1001",
        "CVE-1999-1002",
        "CVE-2999-1003",
        "CVE-1928-1004"
    ]}
    return text, results
