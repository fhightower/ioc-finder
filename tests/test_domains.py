"""Test domains."""

from d8s_lists import iterables_have_same_items

from ioc_finder import find_iocs


def test_issue_104():
    s = '%2Ffreasdfuewriter.com'
    result = find_iocs(s)
    assert 'freasdfuewriter.com' in result['domains']

    s = 'freasdfuewriter.com%2F'
    result = find_iocs(s)
    assert 'freasdfuewriter.com' in result['domains']

    s = 'https://asf.goole.com/mail?url=http%3A%2F%2Ffreasdfuewriter.com%2Fcs%2Fimage%2FCommerciaE.jpg&t=1575955624&ymreqid=733bc9eb-e8f-34cb-1cb5-120010019e00&sig=x2Pa2oOYxanG52s4vyCEFg--~Chttp://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip'
    result = find_iocs(s)
    print(result)
    assert 'freasdfuewriter.com' in result['domains']
