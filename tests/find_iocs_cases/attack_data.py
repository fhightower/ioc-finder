from pytest import param

ATTACK_DATA = [
    param(
        '''Mitigations: 41
        ID  Name    Description
        M1036   Account Use Policies
        Configure features related to account use like login attempt lockouts, specific login times, etc.

        M1015   Active Directory Configuration
        Configur''',
        {'attack_mitigations': {'enterprise': ['M1036', 'M1015'], 'mobile':[]}},
        {},
        id="attack_data_1"
    ),
]
