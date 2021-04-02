# from ioc_finder import find_iocs


# def test_leading_zero():
#     """Sections of IP addresses that start with a leading zero should be interpreted as being in base 8."""
#     s = '0177.0.0.01'
#     results = find_iocs(s)
#     assert results['ipv4s'] == ['127.0.0.1']

#     s = '226.000.000.037'
#     results = find_iocs(s)
#     assert results['ipv4s'] == ['226.0.0.31']

#     s = '014.0.0.01'
#     results = find_iocs(s)
#     assert results['ipv4s'] == ['12.0.0.1']

#     # because `018` (the first section of the ip below) is not a valid octal number, it should not be converted
#     s = '018.0.0.01'
#     results = find_iocs(s)
#     assert results['ipv4s'] == ['18.0.0.1']


# def test_a_b_c_format():
#     results = find_iocs('111.111.1111')
#     assert results['ipv4s'] == ['111.111.4.87']

#     results = find_iocs('10.0.514')
#     assert results['ipv4s'] == ['10.0.2.2']

#     # here is some code to show how sections c and d of dotted decimal form are calculated from the given examples:
#     # x = 1111
#     # print(f'{x // 256}.{(x - 256) % 256}')


# def test_a_b_format():
#     results = find_iocs('1.300')
#     assert results['ipv4s'] == ['1.0.1.44']

#     results = find_iocs('1.256')
#     assert results['ipv4s'] == ['1.0.1.0']

#     results = find_iocs('1.15')
#     assert results['ipv4s'] == ['1.0.0.15']

#     results = find_iocs('1.65793')
#     assert results['ipv4s'] == ['1.1.1.1']

#     results = find_iocs('1.67794')
#     assert results['ipv4s'] == ['1.1.8.210']


# def test_numeric_forms():
#     # these examples are from: https://bugzilla.mozilla.org/show_bug.cgi?id=67730

#     s = 'http://3486011863'
#     results = find_iocs(s)
#     assert results['ipv4s'] == ['207.200.81.215']

#     s = 'http://00000000317.00000000310.00000000121.00000000327/'
#     results = find_iocs(s)
#     assert results['ipv4s'] == ['207.200.81.215']

#     s = 'http://4294967503.4294967496.4294967377.4294967511/'
#     results = find_iocs(s)
#     assert results['ipv4s'] == ['207.200.81.215']


# def test_real_obfuscated_forms():
#     # these examples come from: https://securelist.com/new-brazilian-banking-trojans-recycle-old-url-obfuscation-tricks/29558/

#     s = 'http://0x42.0x66.0x0d.0x63'
#     results = find_iocs(s)
#     assert results['ipv4s'] == ['66.102.13.99']

#     s = 'http://0x42660d63'
#     results = find_iocs(s)
#     assert results['ipv4s'] == ['66.102.13.99']

#     s = 'http://1113984355'
#     results = find_iocs(s)
#     assert results['ipv4s'] == ['66.102.13.99']

#     s = 'http://00000102.00000146.00000015.00000143'
#     results = find_iocs(s)
#     assert results['ipv4s'] == ['66.102.13.99']
