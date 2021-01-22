from ioc_finder import find_iocs


def test_windows_file_paths():
    """."""
    s = r"""C:\Users\<username>\AppData \Local\Microsoft\Windows\shedaudio.exe

C:\Users\<username>\AppData\Roaming\Macromedia\Flash Player\macromedia\bin\flashplayer.exe

Typical Registry Keys:

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run

HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

System Root Directories:

C:\Windows\11987416.exe

C:\Windows\System32\46615275.exe

C:\Windows\System32\shedaudio.exe

C:\Windows\SysWOW64\f9jwqSbS.exe"""
    iocs = find_iocs(s)
    assert len(iocs['file_paths']) == 6
    assert r'C:\Users\<username>\AppData \Local\Microsoft\Windows\shedaudio.exe' in iocs['file_paths']
    assert (
        r'C:\Users\<username>\AppData\Roaming\Macromedia\Flash Player\macromedia\bin\flashplayer.exe'
        in iocs['file_paths']
    )
    assert r'C:\Windows\11987416.exe' in iocs['file_paths']
    assert r'C:\Windows\System32\46615275.exe' in iocs['file_paths']
    assert r'C:\Windows\System32\shedaudio.exe' in iocs['file_paths']
    assert r'C:\Windows\SysWOW64\f9jwqSbS.exe' in iocs['file_paths']


def test_unix_file_paths_simple():
    """."""
    s = '/Library/Storage/File System/HFS/25cf5d02-e50b-4288-870a-528d56c3cf6e/pivtoken.appex'
    iocs = find_iocs(s)['file_paths']
    assert iocs == ['/Library/Storage/File System/HFS/25cf5d02-e50b-4288-870a-528d56c3cf6e/pivtoken.appex']

    s = '~/foo/bar/abc.py'
    iocs = find_iocs(s)['file_paths']
    assert iocs == ['~/foo/bar/abc.py']

    s = './../foo/bar/abc.py'
    iocs = find_iocs(s)['file_paths']
    assert iocs == ['./../foo/bar/abc.py']


def test_unix_file_paths_complex():
    s = 'test /Library/Storage/File System/HFS/25cf5d02-e50b-4288-870a-528d56c3cf6e/pivtoken.appex file'
    file_paths = find_iocs(s)['file_paths']
    assert file_paths == ['/Library/Storage/File System/HFS/25cf5d02-e50b-4288-870a-528d56c3cf6e/pivtoken.appex']

    s = '~/Desktop/test.py'
    iocs = find_iocs(s)
    assert len(iocs['file_paths']) == 1
    assert '~/Desktop/test.py' in iocs['file_paths']

    s = '/etc/init.d/.rebootime'
    iocs = find_iocs(s)
    assert len(iocs['file_paths']) == 1
    assert '/etc/init.d/.rebootime' in iocs['file_paths']
