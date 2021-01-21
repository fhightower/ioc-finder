#!/usr/bin/env python3

from ioc_finder import find_iocs


def test_attack_enterprise_mitigations_1():
    s = '''Mitigations: 41
ID  Name    Description
M1036   Account Use Policies    
Configure features related to account use like login attempt lockouts, specific login times, etc.

M1015   Active Directory Configuration  
Configur'''
    results = find_iocs(s)
    assert list(results['attack_mitigations'].keys()) == ['enterprise', 'mobile']
    assert results['attack_mitigations']['mobile'] == []
    assert 'M1036' in results['attack_mitigations']['enterprise']
    assert 'M1015' in results['attack_mitigations']['enterprise']


def test_attack_mobile_mitigations_1():
    s = ''' Name    Description
M1013   Application Developer Guidance  
This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of.

M1005   Application Vetting 
Enterprises can vet applications for exploitable vulnerabilities or unwanted (privacy-invasive or malicious) behaviors. Enterprises can inspect appl'''
    results = find_iocs(s)
    assert list(results['attack_mitigations'].keys()) == ['enterprise', 'mobile']
    assert results['attack_mitigations']['enterprise'] == ['M1013']
    assert 'M1013' in results['attack_mitigations']['mobile']
    assert 'M1005' in results['attack_mitigations']['mobile']


def test_attack_techniques():
    s = """
ID  Name    Description
T1329   Acquire and/or use 3rd party infrastructure services    
A wide variety of cloud, virtual private services, hosting, compute, and storage solutions are available. Additionally botnets are available for rent or purchase. Use of these solutions allow an adversary to stage, launch, and execute an attack from infrastructure that does not physically tie back to them and can be rapidly provisioned, modified, and shut down.

T1307   Acquire and/or use 3rd party infrastructure services    
A wide variety of cloud, virtual private services, hosting, compute, and storage solutions are available. Additionally botnets are available for rent or purchase. Use of these solutions allow an adversary to stage, launch, and execute an attack from infrastructure that does not physically tie back to them and can be rapidly provisioned, modified, and shut down.

T1308"""
    results = find_iocs(s)
    print(results)
    assert len(results['attack_techniques']) == 3
    assert 'T1329' in results['attack_techniques']['pre_attack']
    assert 'T1307' in results['attack_techniques']['pre_attack']
    assert 'T1308' in results['attack_techniques']['pre_attack']


def test_attack_tactics():
    s = """
    ID  Name    Description
    TA0012  Priority Definition Planning    Priority definition planning consists of the process of determining the set of Key Intelligence Topics (KIT) or Key Intelligence Questions (KIQ) required for meeting key strategic, operational, or tactical goals. Leadership outlines the priority definition (may be considered a goal) around which the adversary designs target selection and a plan to achieve. An analyst may outline the priority definition when in the course of determining gaps in existing KITs or KIQs.
    TA0013  Priority Definition Direction   Priority definition direction consists of the process of collecting and assigning requirements for meeting Key Intelligence Topics (KIT) or Key Intelligence Questions (KIQ) as determined by leadership.
    TA0014  Targ"""
    results = find_iocs(s)
    assert len(results['attack_tactics']) == 3
    assert 'TA0012' in results['attack_tactics']['pre_attack']
    assert 'TA0013' in results['attack_tactics']['pre_attack']
    assert 'TA0014' in results['attack_tactics']['pre_attack']


def test_attack_techniques_edge_cases():
    # make sure attack techniques preceded by some alpha-num. character are not parsed
    s = """FOOT1329"""
    results = find_iocs(s)
    assert results['attack_techniques']['pre_attack'] == []
    assert results['attack_techniques']['enterprise'] == []
    assert results['attack_techniques']['mobile'] == []

    # make sure attack techniques postceded by some alpha-num. character are not parsed
    s = """T1329FUN"""
    results = find_iocs(s)
    assert results['attack_techniques']['pre_attack'] == []
    assert results['attack_techniques']['enterprise'] == []
    assert results['attack_techniques']['mobile'] == []

    # make sure attack techniques preceeded by some alpha-num. character are not parsed
    s = """foot1329"""
    results = find_iocs(s)
    assert results['attack_techniques']['pre_attack'] == []
    assert results['attack_techniques']['enterprise'] == []
    assert results['attack_techniques']['mobile'] == []

    # test lower-case matching
    s = """t1329"""
    results = find_iocs(s)
    print(results)
    assert results['attack_techniques']['pre_attack'] == ['T1329']

    s = 'T1156'
    results = find_iocs(s)
    assert results['attack_techniques']['enterprise'] == ['T1156']

    s = "https://attack.mitre.org/techniques/T1156/"
    results = find_iocs(s)
    assert results['attack_techniques']['enterprise'] == ['T1156']


def test_attack_tactics_edge_cases():
    # make sure attack tactics preceeded by some alpha-num. character are not parsed
    s = """FOOTA0001"""
    results = find_iocs(s)
    assert results['attack_tactics']['pre_attack'] == []
    assert results['attack_tactics']['enterprise'] == []
    assert results['attack_tactics']['mobile'] == []

    s = """AT0001"""
    results = find_iocs(s)
    assert results['attack_tactics']['pre_attack'] == []
    assert results['attack_tactics']['enterprise'] == []
    assert results['attack_tactics']['mobile'] == []

    # make sure attack tactics postceded by some alpha-num. character are not parsed
    s = """TA0001FUN"""
    results = find_iocs(s)
    assert results['attack_tactics']['pre_attack'] == []
    assert results['attack_tactics']['enterprise'] == []
    assert results['attack_tactics']['mobile'] == []

    # make sure attack tactics preceeded by some alpha-num. character are not parsed
    s = """foota0001"""
    results = find_iocs(s)
    assert results['attack_tactics']['pre_attack'] == []
    assert results['attack_tactics']['enterprise'] == []
    assert results['attack_tactics']['mobile'] == []

    # test lower-case matching
    s = """ta0001"""
    results = find_iocs(s)
    assert results['attack_tactics']['enterprise'] == ['TA0001']

    s = "https://attack.mitre.org/tactics/TA0001/"
    results = find_iocs(s)
    assert results['attack_tactics']['enterprise'] == ['TA0001']


def test_subtechnique_parsing():
    s = 'T1546.004'
    results = find_iocs(s)
    assert results['attack_techniques']['enterprise'] == ['T1546.004']

    s = 'T1546.004'
    results = find_iocs(s)
    assert results['attack_techniques']['enterprise'] == ['T1546.004']

    s = 'T1156.0012'
    results = find_iocs(s)
    assert results['attack_techniques']['enterprise'] == []
