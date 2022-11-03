import os
from pathlib import Path

from pytest import mark

from ioc_finder import find_iocs, parse_urls

SHORT_TEXT = """abc.py bar.com example.com foo.com swissjabber.de https://example.com/test%20page/foo.com/bingo.php?q=bar.com foo@swissjabber.de me@example.com me@example.com 1.1.1.1/0 imphash 18ddf28a71089acdbab5038f58044c0a authentihash 3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4 1.1.1.1 2001:0db8:0000:0000:0000:ff00:0042:8329 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 12288:QYV6MorX7qzuC3QHO9FQVHPF51jgcSj2EtPo/V7I6R+Lqaw8i6hG0:vBXu9HGaVHh4Po/VU6RkqaQ6F 0000:0000:ff00 2001:0db8:0000 ASN123 CVE-2022-1234 HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows pub-1234567891234567 UA-000000-1 imphash 18ddf28a71089acdbab5038f58044c0a 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy 496aKKdqF1xQSSEzw7wNrkZkDUsCD5cSmNCfVhVgEps52WERBcLDGzdF5UugmFoHMm9xRJdewvK2TFfAJNwEV25rTcVF5Vp AA-F2-C9-A6-B3-4F Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; InfoPath.1) TLP:RED ~/foo/bar/abc.py enterprise pre_attack pre_attack M1036 M1015 TA0012 T1329"""
LONG_TEXT = Path(os.path.join(os.path.dirname(__file__), "./data/long-article-1.txt")).read_text(encoding="utf8")
TEXTS = (SHORT_TEXT, LONG_TEXT)


def _run(f):
    for text in TEXTS:
        f(text)


def test_benchmarks(benchmark):
    benchmark(_run, find_iocs)


def test_parse_urls(benchmark):
    benchmark(_run, parse_urls)
