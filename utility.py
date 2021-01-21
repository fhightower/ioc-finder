#!/usr/bin/env python3
"""Python package for finding observables in text."""

import requests

PRE_ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json'
ENTERPRISE_ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
MOBILE_ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json'


def _get_id(data):
    return data['external_references'][0]['external_id']


def get_pre_attack_data():
    r = requests.get(PRE_ATTACK_URL)
    l = r.json()['objects']
    tactics = [_get_id(i) for i in l if i['type'] == 'x-mitre-tactic']
    techniques = [_get_id(i) for i in l if i['type'] == 'attack-pattern']
    return tactics, techniques


def get_enterprise_attack_data():
    r = requests.get(ENTERPRISE_ATTACK_URL)
    d = r.json()['objects']
    tactics = [_get_id(i) for i in d if i['type'] == 'x-mitre-tactic']
    techniques = [_get_id(i) for i in d if i['type'] == 'attack-pattern']
    mitigations = [_get_id(i) for i in d if i['type'] == 'course-of-action' and _get_id(i).startswith('M')]
    return tactics, techniques, mitigations


def get_mobile_attack_data():
    r = requests.get(MOBILE_ATTACK_URL)
    d = r.json()['objects']
    tactics = [_get_id(i) for i in d if i['type'] == 'x-mitre-tactic']
    techniques = [_get_id(i) for i in d if i['type'] == 'attack-pattern']
    mitigations = [_get_id(i) for i in d if i['type'] == 'course-of-action' and _get_id(i).startswith('M')]
    return tactics, techniques, mitigations


def get_tlds():
    """."""
    r = requests.get('https://data.iana.org/TLD/tlds-alpha-by-domain.txt')
    tlds = r.text.split('\n')[1:-1]
    tlds = [i.lower() for i in tlds]
    tlds.append('onion')
    return tlds


print(get_pre_attack_data())
print(get_enterprise_attack_data())
print(get_mobile_attack_data())
