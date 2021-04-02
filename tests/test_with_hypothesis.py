"""Using hypothesis (https://hypothesis.readthedocs.io/en/latest/index.html) to test the finder."""

from hypothesis import given, settings
from hypothesis.provisional import domains, urls
from hypothesis.strategies._internal.ipaddress import ip_addresses

from ioc_finder import find_iocs


# @given(urls())
# @settings(deadline=None)
# def test_url_parsing(url):
#     url = url.lower()
#     iocs = find_iocs(url)
#     failure = False

#     try:
#         assert len(iocs['urls']) == 1
#         assert iocs['urls'][0] == url
#     except AssertionError as e:
#         failure = True
#         print('Failed on url: {}'.format(url))

#     if failure:
#         raise AssertionError('Error parsing urls')


# @given(domains())
# @settings(deadline=None)
# def test_domain_parsing(domain):
#     domain = domain.lower()
#     iocs = find_iocs(domain)
#     failure = False

#     try:
#         assert len(iocs['domains']) == 1
#         assert iocs['domains'][0] == domain
#     except AssertionError as e:
#         failure = True
#         print('Failed on domain: {}'.format(domain))

#     if failure:
#         raise AssertionError('Error parsing domains')


# @given(ip_addresses(v=4))
# @settings(deadline=None)
# def test_ipv4_parsing(ipv4):
#     iocs = find_iocs(ipv4)
#     failure = False

#     try:
#         assert len(iocs['ipv4s']) == 1
#         assert iocs['ipv4s'][0] == ipv4
#     except AssertionError as e:
#         failure = True
#         print('Failed on ipv4: {}'.format(ipv4))

#     if failure:
#         raise AssertionError('Error parsing ipv4s')


# @given(ip_addresses(v=6))
# @settings(deadline=None)
# def test_ipv6_parsing(ipv6):
#     iocs = find_iocs(ipv6)
#     failure = False

#     try:
#         assert len(iocs['ipv6s']) == 1
#         assert iocs['ipv6s'][0] == ipv6
#     except AssertionError as e:
#         failure = True
#         print('Failed on ipv6: {}'.format(ipv6))

#     if failure:
#         raise AssertionError('Error parsing ipv6s')
