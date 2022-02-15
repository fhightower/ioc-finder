from .tlp_labels import case_tlp_label_len_2, case_tlp_label_len_3
from .domains import case_domain_google_and_example
from .email import case_email_len_10_and_ipv4
from .hashes import case_multiple_hashes_simple
from .cves import case_cve_simple
from .ip_addr import case_ipv4_addr_cidr, case_ipv4_addr_simple, case_ipv6_addr_simple

# __all__ = ["case_tlp_len_2", "case_tlp_len_3"]

cases = [case_tlp_label_len_2, case_tlp_label_len_3,
         case_domain_google_and_example,
         case_email_len_10_and_ipv4,
         case_multiple_hashes_simple,
         case_cve_simple,
         case_ipv4_addr_cidr, case_ipv4_addr_simple, case_ipv6_addr_simple
         ]
