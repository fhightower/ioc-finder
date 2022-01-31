from ioc_finder import find_iocs
text = "This is just an example.com https://example.org/test/bingo.php example[.]com example.com T1031"
iocs, pos_map = find_iocs(text)
#print('Domains: {}'.format(iocs['domains']))
#print('URLs: {}'.format(iocs['urls']))

for k in iocs.keys():
    if len(iocs[k]) > 0:
        print('---------------------')
        print(k.upper())
        for el in iocs[k]:
            print('\t {}:{}'.format(el, pos_map[k][el]))
