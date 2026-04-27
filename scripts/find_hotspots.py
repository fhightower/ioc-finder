"""Identify which parse_* function in find_iocs is slowest, and back that up
with a cProfile drill-down.

Usage:
    uv run python scripts/find_hotspots.py

Two views are printed:

1. Per-grammar wall time on the long benchmark article. This tells you which
   `parse_*` helper to attack first.
2. Top cumulative-time entries from cProfile across both benchmark texts. This
   confirms the per-grammar numbers and surfaces which pyparsing internals
   each helper is paying for.

Run this before tuning any parse_* helper, and again after, to make sure the
"slow" thing actually moved.
"""

from __future__ import annotations

import cProfile
import io
import os
import pstats
import time
import warnings
from pathlib import Path

# Pyparsing emits a DeprecationWarning for every searchString/scanString call
# in this codebase, which floods the output. They are not what we're measuring.
warnings.filterwarnings("ignore", category=DeprecationWarning)

from ioc_finder import DEFAULT_IOC_TYPES, find_iocs
from ioc_finder import ioc_finder as I

LONG_TEXT = Path(os.path.join(os.path.dirname(__file__), "..", "tests", "data", "long-article-1.txt")).read_text(
    encoding="utf8"
)
SHORT_TEXT = (
    "abc.py bar.com example.com foo@example.com 1.1.1.1 "
    "2001:0db8:0000:0000:0000:ff00:0042:8329 "
    "imphash 18ddf28a71089acdbab5038f58044c0a "
    "AA-F2-C9-A6-B3-4F Mozilla/4.0 (compatible; MSIE 7.0b)"
)

# (label, callable). Order matches the order parse_* helpers are called inside
# find_iocs so the table reads top-to-bottom like the pipeline.
# Maps each label to its parser and the ioc_type key produced in find_iocs output
# (used to flag labels that are part of DEFAULT_IOC_TYPES with a "*" in the report).
GRAMMARS = [
    ("urls", I.parse_urls, "urls"),
    ("urls_complete", I.parse_urls_complete, "urls_complete"),
    ("complete_email", I.parse_complete_email_addresses, "email_addresses_complete"),
    ("email", I.parse_email_addresses, "email_addresses"),
    ("ipv6", I.parse_ipv6_addresses, "ipv6s"),
    ("ipv4", I.parse_ipv4_addresses, "ipv4s"),
    ("imphashes", I.parse_imphashes_, "imphashes"),
    ("authentihashes", I.parse_authentihashes_, "authentihashes"),
    ("md5", I.parse_md5s, "md5s"),
    ("sha1", I.parse_sha1s, "sha1s"),
    ("sha256", I.parse_sha256s, "sha256s"),
    ("sha512", I.parse_sha512s, "sha512s"),
    ("ssdeep", I.parse_ssdeeps, "ssdeeps"),
    ("domains", I.parse_domain_names, "domains"),
    ("asns", I.parse_asns, "asns"),
    ("cves", I.parse_cves, "cves"),
    ("registry_key_paths", I.parse_registry_key_paths, "registry_key_paths"),
    ("bitcoin", I.parse_bitcoin_addresses, "bitcoin_addresses"),
    ("monero", I.parse_monero_addresses, "monero_addresses"),
    ("xmpp", I.parse_xmpp_addresses, "xmpp_addresses"),
    ("mac", I.parse_mac_addresses, "mac_addresses"),
    ("user_agents", I.parse_user_agents, "user_agents"),
    ("file_paths", I.parse_file_paths, "file_paths"),
    ("tlp_labels", I.parse_tlp_labels, "tlp_labels"),
]

DEFAULT_LABELS = {label for label, _, ioc_type in GRAMMARS if ioc_type in DEFAULT_IOC_TYPES}

REPEATS = 3


def per_grammar_timings(text: str) -> list[tuple[str, float]]:
    """Return (label, mean_ms_per_run) sorted slowest first."""
    # Warm up once so first-call overhead (regex compile, grammar build cache)
    # doesn't get charged to whichever helper happens to run first.
    for _, fn, _ in GRAMMARS:
        fn(text)

    rows = []
    for label, fn, _ in GRAMMARS:
        start = time.perf_counter()
        for _ in range(REPEATS):
            fn(text)
        elapsed_ms = (time.perf_counter() - start) / REPEATS * 1000
        rows.append((label, elapsed_ms))
    rows.sort(key=lambda r: r[1], reverse=True)
    return rows


def cprofile_top(text_short: str, text_long: str, n: int = 25) -> str:
    """Run find_iocs through cProfile and return the top-n cumulative entries."""
    # Warm up so import/regex/grammar-build costs aren't charged to the profile.
    find_iocs(text_short)
    find_iocs(text_long)

    pr = cProfile.Profile()
    pr.enable()
    for _ in range(REPEATS):
        find_iocs(text_short)
        find_iocs(text_long)
    pr.disable()

    buf = io.StringIO()
    pstats.Stats(pr, stream=buf).sort_stats("cumulative").print_stats(n)
    return buf.getvalue()


def main() -> None:
    print(f"Long article length: {len(LONG_TEXT)} chars\n")

    print(f"== Per-grammar timings on long article (mean of {REPEATS} runs, sorted slowest first) ==")
    print("   (* = part of DEFAULT_IOC_TYPES)")
    rows = per_grammar_timings(LONG_TEXT)
    width = max(len(label) for label, _ in rows)
    for label, ms in rows:
        marker = "*" if label in DEFAULT_LABELS else " "
        print(f"  {marker} {label:<{width}}  {ms:7.1f} ms")

    print("\n== cProfile cumulative top entries for find_iocs(short) + find_iocs(long) ==")
    print(cprofile_top(SHORT_TEXT, LONG_TEXT))


if __name__ == "__main__":
    main()
