from pytest import param

ATTACK_DATA = [
    param(
        """Mitigations: 41
        ID  Name    Description
        M1036   Account Use Policies
        Configure features related to account use like login attempt lockouts, specific login times, etc.

        M1015   Active Directory Configuration
        Configur""",
        {"attack_mitigations": {"enterprise": ["M1036", "M1015"]}},
        {},
        id="attack_data_1",
    ),
    param(
        """ Name    Description
        M1013   Application Developer Guidance
        This mitigation describes any guidance or training given to developers of applications to avoid introducing security weaknesses that an adversary may be able to take advantage of.

        M1005   Application Vetting
        Enterprises can vet applications for exploitable vulnerabilities or unwanted (privacy-invasive or malicious) behaviors. Enterprises can inspect appl""",
        {"attack_mitigations": {"enterprise": ["M1013"], "mobile": ["M1013", "M1005"]}},
        {},
        id="attack_data_2",
    ),
    param(
        """
        ID  Name    Description
        T1329   Acquire and/or use 3rd party infrastructure services
        A wide variety of cloud, virtual private services, hosting, compute, and storage solutions are available. Additionally botnets are available for rent or purchase. Use of these solutions allow an adversary to stage, launch, and execute an attack from infrastructure that does not physically tie back to them and can be rapidly provisioned, modified, and shut down.

        T1307   Acquire and/or use 3rd party infrastructure services
        A wide variety of cloud, virtual private services, hosting, compute, and storage solutions are available. Additionally botnets are available for rent or purchase. Use of these solutions allow an adversary to stage, launch, and execute an attack from infrastructure that does not physically tie back to them and can be rapidly provisioned, modified, and shut down.

        T1308""",
        {"attack_techniques": {"pre_attack": ["T1329", "T1307", "T1308"]}},
        {},
        id="attack_pattern_3",
    ),
    param(
        """
        ID  Name    Description
        TA0012  Priority Definition Planning    Priority definition planning consists of the process of determining the set of Key Intelligence Topics (KIT) or Key Intelligence Questions (KIQ) required for meeting key strategic, operational, or tactical goals. Leadership outlines the priority definition (may be considered a goal) around which the adversary designs target selection and a plan to achieve. An analyst may outline the priority definition when in the course of determining gaps in existing KITs or KIQs.
        TA0013  Priority Definition Direction   Priority definition direction consists of the process of collecting and assigning requirements for meeting Key Intelligence Topics (KIT) or Key Intelligence Questions (KIQ) as determined by leadership.
        TA0014  Targ""",
        {"attack_tactics": {"pre_attack": ["TA0012", "TA0013", "TA0014"]}},
        {},
        id="attack_pattern_4",
    ),
    param("""FOOT1329""", {}, {}, id="attack_pattern_5"),
    param("""T1329FUN""", {}, {}, id="attack_pattern_6"),
    param("""foot1329""", {}, {}, id="attack_pattern_7"),
    param("""t1329""", {"attack_techniques": {"pre_attack": ["T1329"]}}, {}, id="attack_pattern_8"),
    param("T1156", {"attack_techniques": {"enterprise": ["T1156"]}}, {}, id="attack_pattern_9"),
    param("AT0001", {}, {}, id="attack_pattern_10"),
    param("TA0001FUN", {}, {}, id="attack_pattern_11"),
    param("foota0001", {}, {}, id="attack_pattern_12"),
    param("ta0001", {"attack_tactics": {"enterprise": ["TA0001"]}}, {}, id="attack_pattern_13"),
    param(
        "https://attack.mitre.org/tactics/TA0001/",
        {
            "attack_tactics": {"enterprise": ["TA0001"]},
            "urls": ["https://attack.mitre.org/tactics/TA0001/"],
            "domains": ["attack.mitre.org"],
        },
        {},
        id="attack_pattern_14",
    ),
    param("T1546.004", {"attack_techniques": {"enterprise": ["T1546.004"]}}, {}, id="attack_pattern_15"),
    param("T1156.0012", {}, {}, id="attack_pattern_16"),
]
