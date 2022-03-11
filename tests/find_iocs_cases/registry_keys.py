from pytest import param

REGISTRY_DATA = [
    # see https://github.com/fhightower/ioc-finder/issues/63 - matching registry key paths with content between '<' and '>'
    param(
        'The registry value “ntdll” was added to the “HKEY_USERS\<USER SID>\Software\Microsoft\Windows\CurrentVersion\Run” key.',
        {'registry_key_paths': ['HKEY_USERS\<USER SID>\Software\Microsoft\Windows\CurrentVersion\Run']},
        {},
        id="registry_1"
    ),
    param(
        "The registry value “ntdll” was added to the “HKEY_USERS\<USER SID\Software\Microsoft\Windows\CurrentVersion\Run” key.",
        {},
        {},
        id="registry_2"
    ),
    param(
        """<HKCU>\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED
        Value Name: ShowSuperHidden
        <HKCU>\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED
        Value Name: HideFileExt
        <HKCU>\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED
        Value Name: SuperHidden
        <HKLM>\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED\FOLDER\HIDEFILEEXT
        Value Name: DefaultValue
        <HKLM>\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\EXPLORER\RUN
        Value Name: PC
        <HKLM>\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN
        Value Name: avscan""",
        {'registry_key_paths': [
            "HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED",
            "HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED\FOLDER\HIDEFILEEXT",
            "HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\EXPLORER\RUN",
            "HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN"
        ]
        },
        {},
        id="registry_3"
    ),
    param(
        """HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\ConsoleIME HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN""",
        {'registry_key_paths': ["HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\ConsoleIME",
                                "HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN"]},
        {},
        id="registry_4"
    ),
    param(
        """HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\ConsoleIME""",
        {'registry_key_paths': ['HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\ConsoleIME']},
        {},
        id="registry_5"
    ),
    param(
        """Found a registry key like <HKCU>\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED on the windows box""",
        {'registry_key_paths': ['HKCU\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\EXPLORER\ADVANCED']},
        {},
        id="registry_6"
    ),
    param(
        """Found a registry key like HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\ConsoleIME on the windows box""",
        {'registry_key_paths': ['HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\ConsoleIME']},
        {},
        id="registry_7"
    ),
    param(
        'HKLM\\SOFTWARE\\foo bar\\b',
        {'registry_key_paths': ['HKLM\\SOFTWARE\\foo bar\\b']},
        {},
        id="registry_8"
    ),
    param(
        'HKLM\\SOFTWARE\\foo bar\\bing buzz\\b',
        {'registry_key_paths': ['HKLM\\SOFTWARE\\foo bar\\bing buzz\\b']},
        {},
        id="registry_9"
    ),
    param(
        'HKLM\\SOFTWARE\\foo bar bing\\buzz boom\\b',
        {'registry_key_paths': ['HKLM\\SOFTWARE\\foo bar bing\\buzz boom\\b']},
        {},
        id="registry_10"
    ),
    param(
        'HKLM\\SOFTWARE\\foo bar\\bing buzz boom\\b',
        {'registry_key_paths': ['HKLM\\SOFTWARE\\foo bar\\bing buzz boom\\b']},
        {},
        id="registry_11"
    ),
    param(
        'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\notepad.exe',
        {'registry_key_paths': [
            'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\notepad.exe']},
        {},
        id="registry_12"
    ),
    param(
        """HKLM\SOFTWARE\Microsoft\Windows  NT\CurrentVersion\Console\ConsoleIME""",
        {'registry_key_paths': [
            'HKLM\SOFTWARE\Microsoft\Windows']},
        {},
        id="registry_13"
    )
]
