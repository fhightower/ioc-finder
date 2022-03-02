from .tlp_labels import TLP_DATA
from .domains import DOMAIN_DATA
from .email import EMAIL_DATA
from .hashes import HASH_DATA
from .cves import CVE_DATA
from .ip_addr import IP_DATA

cases = [TLP_DATA,
         DOMAIN_DATA,
         EMAIL_DATA,
         HASH_DATA,
         CVE_DATA,
         IP_DATA
         ]

ALL_TESTS = [val for sublist in cases for val in sublist]

