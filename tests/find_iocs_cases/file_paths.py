from pytest import param

PATH_DATA = [
    param(
        """C:\\Users\\<username>\\AppData \\Local\\Microsoft\\Windows\\shedaudio.exe

        C:\\Users\\<username>\\AppData\\Roaming\\Macromedia\\Flash Player\\macromedia\\bin\\flashplayer.exe

        Typical Registry Keys:

        HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

        HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run

        HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

        System Root Directories:

        C:\\Windows\\11987416.exe

        C:\\Windows\\System32\\46615275.exe

        C:\\Windows\\System32\\shedaudio.exe

        C:\\Windows\\SysWOW64\\f9jwqSbS.exe""",
        {
            "file_paths": [
                "C:\\Users\\<username>\\AppData \\Local\\Microsoft\\Windows\\shedaudio.exe",
                "C:\\Users\\<username>\\AppData\\Roaming\\Macromedia\\Flash Player\\macromedia\\bin\\flashplayer.exe",
                "C:\\Windows\\11987416.exe",
                "C:\\Windows\\System32\\46615275.exe",
                "C:\\Windows\\System32\\shedaudio.exe",
                "C:\\Windows\\SysWOW64\\f9jwqSbS.exe",
            ],
            "registry_key_paths": [
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ],
        },
        {},
        id="file_path_1",
    ),
    param(
        "/Library/Storage/File System/HFS/25cf5d02-e50b-4288-870a-528d56c3cf6e/pivtoken.appex",
        {"file_paths": ["/Library/Storage/File System/HFS/25cf5d02-e50b-4288-870a-528d56c3cf6e/pivtoken.appex"]},
        {},
        id="file_path_2",
    ),
    param(
        "and this is a file ~/foo/bar/abc.py",
        {"file_paths": ["~/foo/bar/abc.py"], "domains": ["abc.py"]},
        {},
        id="file_path_3",
    ),
    param(
        "test /Library/Storage/File System/HFS/25cf5d02-e50b-4288-870a-528d56c3cf6e/pivtoken.appex file",
        {"file_paths": ["/Library/Storage/File System/HFS/25cf5d02-e50b-4288-870a-528d56c3cf6e/pivtoken.appex"]},
        {},
        id="file_path_4",
    ),
    param(
        "another home directory ~/Desktop/test.py python file",
        {"file_paths": ["~/Desktop/test.py"], "domains": ["test.py"]},
        {},
        id="file_path_5",
    ),
    # param(
    #     "/Library/Storage/File System/HFS/25cf5d02-e50b-4288-870a-528d56c3cf6e/pivtoken.appex",
    #     {'file_paths': ["/Library/Storage/File System/HFS/25cf5d02-e50b-4288-870a-528d56c3cf6e/pivtoken.appex"]},
    #     {},
    #     id="file_path_2"
    # )
]
