from .cves import CVE_DATA
from .domains import DOMAIN_DATA

TEST_LISTS = [CVE_DATA, DOMAIN_DATA]
ALL_TESTS = [val for sublist in TEST_LISTS for val in sublist]
