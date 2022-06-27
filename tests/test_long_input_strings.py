from pathlib import Path
import os
from time import perf_counter
import logging

from ioc_finder import find_iocs

CURR_DIR = os.path.dirname(__file__)


def test_long_article_1():
    article_1 = Path(os.path.join(CURR_DIR, "./data/long-article-1.txt"))
    article_1_string = article_1.read_text()
    start = perf_counter()
    iocs = find_iocs(article_1_string)
    end = perf_counter()
    print(end - start)
    assert 1 == 2

