"""Python package for finding observables in text."""

import json
import logging
import re
import urllib.parse as urlparse
from collections.abc import Callable, Iterable, Iterator, Mapping
from string import hexdigits

import click
import ioc_fanger
from pyparsing import ParseException, ParseResults

from ioc_finder import ioc_grammars

logger = logging.getLogger(__name__)

# `parse_domain_names` consults `ioc_grammars.TLD_SET` directly so the fast
# path and the `domain_name` grammar (used as a sub-grammar in email/url/xmpp)
# can't drift on which strings are considered TLDs.

# Cheap regexes used to locate ATT&CK-ID-shaped candidate spans so the
# pyparsing grammars (which carry alternations of hundreds of literal IDs)
# only run where a match could plausibly occur rather than at every offset.
# The leading lookbehind mirrors ioc_grammars.alphanum_word_start, which only
# treats ASCII alphanumerics as word chars. Trailing char classes greedily
# consume any remaining alphanumerics (and dots, for techniques with
# sub-technique suffixes) so the grammar is handed the full token and can
# apply its own word-end check — e.g. "T1156.0012" must reach the grammar
# intact so it can be correctly rejected rather than truncated to "T1156".
_ATTACK_MITIGATION_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])M\d{4}[A-Za-z0-9]*", re.IGNORECASE)
_ATTACK_TACTIC_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])TA\d{4}[A-Za-z0-9]*", re.IGNORECASE)
_ATTACK_TECHNIQUE_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])T\d{4}[A-Za-z0-9.]*", re.IGNORECASE)

# A dotted run of label-like chars — cheap regex used to locate candidate domain
# spans. Each label is capped at 63 chars to mirror ioc_grammars.label
# (`Word(..., max=63)`); without the cap, a too-long-label run would over-capture
# and hide an embedded valid domain (e.g. "<100 a's>.bar.com" → "bar.com" still
# wants to surface). Char classes are ASCII-only; the Unicode counterpart used
# when find_iocs(..., parse_unicode_iocs=True) is `_DOMAIN_CANDIDATE_RE_UNICODE`
# below (which tracks the Unicode `domain_labels` pattern in ioc_grammars).
_DOMAIN_CANDIDATE_RE = re.compile(
    # Boundaries mirror ioc_grammars.alphanum_word_start / alphanum_word_end,
    # which only treat ASCII alphanumerics as word chars — so a domain may
    # start right after '-' or '_' (e.g. "(-example.com)", "abc.-def.com").
    r"(?<![A-Za-z0-9])"
    r"[A-Za-z0-9_][A-Za-z0-9_-]{0,62}"
    r"(?:\.[A-Za-z0-9_][A-Za-z0-9_-]{0,62})+"
    r"(?![A-Za-z0-9])"
)

# Cheap candidate-span regexes used to anchor the more expensive pyparsing
# grammars on plausible matches, mirroring the _DOMAIN_CANDIDATE_RE pattern.
# Each is intentionally a superset of what its grammar accepts — pyparsing
# applies the precise rules; the regex only narrows where pyparsing runs.

# Email candidates are located by anchoring on '@' and expanding outward in
# Python (see `_email_candidate_spans`), NOT with a single `(?:local+)@domain`
# regex. A leading `(?:...)+` before '@' makes `re` restart at every offset and
# re-walk the whole run on input that never reaches an '@' (a base64/hex blob is
# all local-part chars), which is O(n²) — the same trap `_URL_MARKER_RE` avoids.
# `_EMAIL_LOCAL_CHARS` mirrors complete_email_local_part (alphanums + the special
# chars listed in ioc_grammars + '"' for quoted locals + '()' for email comments
# + '\\' so a backslash-escaped at-sign stays inside the local part, cf.
# "Abc\@def@example.com" in test_edge_cases). The domain tail is applied with
# `.match()` at a fixed offset just past '@' (anchored → linear) and accepts a
# domain-shaped run or a bracketed IP literal ("[192.168.0.1]", "[IPv6:...]").
_EMAIL_LOCAL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-/=?^_`{|}~.\"()\\"
)
_EMAIL_DOMAIN_TAIL_RE = re.compile(r"\[[^\]\s]{1,80}\]|[A-Za-z0-9._\-]+")

# IPv6 candidates: hex+colon runs that contain at least two colons. Boundaries
# mirror ipv6_word_start / ipv6_word_end (alphanums + ':' as word chars). Every
# valid IPv6 has >=2 colons (full form has 7; shortened requires '::'), so this
# excludes plain hex blobs (md5/sha1/sha256, hex bytes) that previously got fed
# to the grammar only to fail there. The grammar still validates the full
# structure, valid hexadectet count, and '::' shortening rules.
_IPV6_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9:])(?:[0-9A-Fa-f]*:){2,}[0-9A-Fa-f]*(?![A-Za-z0-9:])")

# IPv4 candidates: four 1–3 digit groups separated by dots. The lookbehind
# mirrors alphanum_word_start + WordStart("." + nums) — neither alphanumeric
# nor '.' may precede. The trailing `(?!\.\S)` mirrors NotAny(r"\.\S") so a
# fifth dotted segment ("1.2.3.4.5") is excluded. The per-octet `<256` check
# and the grammar's leading-zero normalization are applied by
# `_normalized_ipv4` (pure Python — see parse_ipv4_addresses), which rejects
# e.g. "999.1.1.1". Octets are `[0-9]`, not `\d`: with the ipv4_address
# grammar (whose Word(nums) is ASCII-only) no longer run on these spans,
# a Unicode-aware `\d` would let int() fabricate addresses from non-ASCII
# digit runs like "١.٢.٣.٤" / "１.２.３.４". The `(?<!\d)` / `(?!\d)`
# lookarounds ARE Unicode-aware on purpose: they mirror the `\b` implied by
# the grammar's `Word(nums, as_keyword=True)` octets, which rejected a quad
# hugging a non-ASCII digit ("٣3.2.3.4", "1.2.3.4٣") because `\b` treats
# the adjacent digit as a word character. Enforcing that here fixes a leak
# in the old regex+grammar pipeline rather than diverging from it: because
# _scan_candidates runs the grammar on an *isolated* span, a hugging digit
# that regex backtracking pushed outside the span was invisible to the
# grammar's `\b`, so the same quad was accepted or rejected depending on
# surrounding text ("١010.0.0.1" -> "10.0.0.1" and "1.2.3.4٣.5" ->
# "1.2.3.4" were accepted; bare "٣3.2.3.4" / "1.2.3.4٣" were rejected).
# The lookarounds apply the grammar's own boundary rule to every
# hugging-digit case; pinned in test_unicode_digits_are_not_parsed_as_ipv4s.
_IPV4_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9.])(?<!\d)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\d)(?![A-Za-z0-9])(?!\.\S)")

# Hash candidates: a hex run of exactly 32/40/64 chars. The leading lookbehind
# mirrors file_hash_word_start (word_chars = alphanums minus 'x'/'X'), so a
# leading 'x'/'X' prefix is allowed (issue #41). The trailing lookahead mirrors
# alphanum_word_end so a longer hex run isn't sliced into a shorter hash —
# e.g. a 64-char run won't surface as an MD5 candidate.
# NOTE: exact mirrors of their grammars, not supersets, and used as the sole
# validators — see _scan_hash_candidates for the full contract.
_MD5_CANDIDATE_RE = re.compile(r"(?<![A-WYZa-wyz0-9])[A-Fa-f0-9]{32}(?![A-Za-z0-9])")
_SHA1_CANDIDATE_RE = re.compile(r"(?<![A-WYZa-wyz0-9])[A-Fa-f0-9]{40}(?![A-Za-z0-9])")
_SHA256_CANDIDATE_RE = re.compile(r"(?<![A-WYZa-wyz0-9])[A-Fa-f0-9]{64}(?![A-Za-z0-9])")

# CVE candidates: "CVE" + dash/space separators + 4-digit year (1xxx/2xxx) + dashes
# + 4-or-more digit id. Mirrors `year = Regex(r"[12][0-9]{3}")` and the trailing
# `Word(nums, min=4)` + alphanum_word_end. Case-insensitive to match
# CaselessLiteral("cve"). Digits are `[0-9]`, not `\d`, to match the ASCII-only
# grammar rather than relying on it to reject non-ASCII digit runs.
_CVE_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9])cve[- ]+[12][0-9]{3}-+[0-9]{4,}(?![A-Za-z0-9])",
    re.IGNORECASE,
)

# imphash / authentihash candidates: the literal keyword (case-insensitive),
# any run of non-alphanumeric separator chars (matching the grammar's
# Optional(Word(printables, excludeChars=alphanums))), then the hash.
# The trailing lookahead mirrors the grammar's alphanum_word_end so we don't
# slice a 32/64-char window out of a longer hex run.
_IMPHASH_CANDIDATE_RE = re.compile(r"(?:imphash|import hash)[^a-z0-9]*[a-f0-9]{32}(?![a-z0-9])")
_AUTHENTIHASH_CANDIDATE_RE = re.compile(r"authentihash[^a-z0-9]*[a-f0-9]{64}(?![a-z0-9])")

# URL marker: '://' (scheme present), '.<tld>[:port]/' (scheme-less URL with
# a path), or the tail of an IPv4-shaped host + optional port + '/' (the
# scheme_less_url grammar's url_authority accepts ipv4_address hosts, and the
# letter-after-dot marker can never fire on one). The candidate span is built in Python by
# expanding from each marker out to whitespace boundaries (see
# `_url_candidate_spans`). A pure regex of the form `\S*<marker>\S*` would go
# quadratic on long non-whitespace, non-URL runs (e.g. 10k bytes of base64)
# because the leading `\S*` walks to the end and backtracks for each starting
# offset; every alternative here is anchored (no leading unbounded
# quantifier), so the scan stays linear. The markers are locators only — the
# URL grammars remain the validators (e.g. `999.1.2.3/x` produces a candidate
# span the grammar then rejects). Digits are `[0-9]`, not `\d`, purely for
# consistency with the other candidate regexes here; the grammar would reject
# non-ASCII digits either way.
#
# The IPv4 alternative excludes the bare-CIDR shape (quad + '/' + one or two
# digits ending the whitespace-delimited token). Without that exclusion every
# `10.0.0.0/8` in a netblock feed or firewall dump becomes a candidate span,
# and the ~750µs of grammar work it costs is pure waste: `find_iocs` strips
# the resulting "URL" again in the issue-#91 removal pass, and standalone
# `parse_urls("10.0.0.0/8")` returned nothing before the IPv4 marker existed.
# The exclusion is deliberately narrow — anything after the digits (`/8.php`,
# `/12?a=b`, `/80/x`) still marks — so a CIDR trailed by prose punctuation
# ("10.0.0.0/8.") does still pay for a candidate span. Bulk CIDR text, the
# case that actually matters for throughput, is whitespace-delimited.
#
# The IPv4 alternative matches only the last two octets (`.3.4/`), not the
# whole quad, so that it starts with a literal '.' like the alternative above
# it. This matters a lot: `re` prefilters a branch by the set of characters
# that can start it, and leading the alternation with `[0-9]` widens that set
# enough to defeat the skip — the full-quad form scanned the benchmark corpus
# in 1.21ms against 0.15ms for the two original alternatives, an 8x cost for
# an identical set of hits. Matching the tail costs nothing in coverage: every
# quad + '/' contains `.<octet>.<octet>/`, and markers only locate the span
# (`_url_candidate_spans` expands back to the whitespace boundaries), so the
# leading octets are recovered anyway. It does let a non-quad like `v1.2.3/x`
# mark, which is fine — that is what "locators only" buys.
#
# Not covered: bracketed IPv6 hosts (`[2001:db8::1]:8080/gate.php`). Adding a
# marker for them would not help — the url grammars reject the scheme-*ful*
# form too, so that is a grammar gap rather than a marker gap.
_URL_MARKER_RE = re.compile(
    r"://"
    r"|\.[A-Za-z][A-Za-z0-9-]*(?::[0-9]{1,5})?/"
    r"|\.[0-9]{1,3}\.[0-9]{1,3}(?::[0-9]{1,5})?/(?![0-9]{1,2}(?!\S))"
)

# MAC candidates: the three notations the grammar accepts —
# `xx[:-]xx[:-]xx[:-]xx[:-]xx[:-]xx` (mixed colon/dash separators allowed)
# and `xxxx.xxxx.xxxx`. Boundaries mirror mac_address_word_start /
# mac_address_word_end (wordChars = alphanums + ":-.").
_MAC_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9:.\-])"
    r"(?:"
    r"[0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5}"
    r"|"
    r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}"
    r")"
    r"(?![A-Za-z0-9:.\-])"
)

# User-agent candidates: the grammar requires the string to start with
# `[Mm]ozilla/<version>`. We anchor on that prefix and take the run up to
# the next Mozilla start (or end of input) so the grammar can split a line
# containing two concatenated user agents into two matches.
_USER_AGENT_START_RE = re.compile(r"[Mm]ozilla/\d")

# ASN candidates: a leading "AS" / "as" / "asn" (the grammar uses
# case-sensitive Literal()s — "AS" with optional "N "/spaces, lowercase "as",
# or lowercase "asn" with optional space) followed by digits. Boundaries
# mirror alphanum_word_start / alphanum_word_end. The grammar still
# normalizes to "ASN<n>".
#
# Order matters and we rely on regex backtracking — `as` is tried before
# `asn ?`, but if `\d+` fails after `as` (e.g. on "asn123" the next char is
# 'n'), the engine retries `asn ?` and `\d+` succeeds. Don't add
# re.IGNORECASE; the grammar's Literal()s are case-sensitive.
_ASN_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])(?:AS[N ]*|as|asn ?)\d+(?![A-Za-z0-9])")

# TLP-label candidates: literal "tlp" (caseless) + optional ":" / "-" / " "
# separator + one of the four colors (caseless). The grammar has no
# alphanum boundary, so neither does the candidate.
_TLP_CANDIDATE_RE = re.compile(
    r"tlp[:\- ]?(?:red|amber|green|white)",
    re.IGNORECASE,
)

# SHA512 candidates: a hex run of exactly 128 chars. Same boundary trick as
# the md5/sha1/sha256 prefilters — file_hash_word_start lets a leading
# 'x'/'X' through (issue #41), and the trailing alphanum_word_end keeps a
# longer hex run from being sliced down.
_SHA512_CANDIDATE_RE = re.compile(r"(?<![A-WYZa-wyz0-9])[A-Fa-f0-9]{128}(?![A-Za-z0-9])")

# Registry-key-path candidates: optional '<' + one of the case-sensitive
# root-key literals + optional '>' + at least one '\' + the rest of the line.
# The grammar enforces sub-path structure, the bracket-balance condition,
# and the no-double-space rule — over-grabbing the rest of the line is fine
# because scan_string will find the actual terminus.
_REGISTRY_KEY_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"<?(?:HKEY_(?:PERFORMANCE_DATA|CURRENT_CONFIG|LOCAL_MACHINE|CLASSES_ROOT|CURRENT_USER|DYN_DATA|USERS)|HKLM|HKCC|HKCR|HKCU|HKU)>?"
    r"\\[^\r\n]*"
)

# XMPP candidates: an email-shaped span where the domain contains "jabber"
# or "xmpp". The grammar's condition runs on the post-downcase domain so we
# match those keywords case-insensitively (inline `(?i:...)` only on the
# keyword — the surrounding char classes are already biscriptal). Local-part
# chars mirror email_local_part (alphanum init, alphanum+`+-_.` body);
# domain chars mirror domain_name's label body (alphanums + `_-` and `.`
# between labels).
#
# The leading domain run is lazy (`*?`) so that a long jabber/xmpp-free
# domain doesn't trigger O(n²) backtracking — the prefilter is a superset
# and the grammar still validates the actual span.
_XMPP_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"[A-Za-z0-9][A-Za-z0-9+\-_.]*"
    r"@"
    r"[A-Za-z0-9._\-]*?(?i:jabber|xmpp)[A-Za-z0-9._\-]*"
)

# Unicode-aware variants of the domain / email / XMPP candidate regexes, used
# when find_iocs(..., parse_unicode_iocs=True). They differ from their ASCII
# counterparts above in the domain-label character class: `\w` (Unicode letters
# of any script + digits + "_") in place of `[A-Za-z0-9_]`. The word-boundary
# lookarounds use `[^\W_]` ("Unicode alphanumeric", no underscore) — in Unicode
# mode a non-ASCII letter is a word character, so e.g. `example.com中` is one
# word and yields no domain (mirroring how `example.comX` yields none in ASCII
# mode), whereas ASCII mode treats the `中` as a boundary and reports
# `example.com`. This is a deliberate semantic difference, covered by
# `test_unicode_boundary_semantics`.
#
# Scope: the rule applies to *bare domains only*. The email/URL/XMPP grammars
# keep the ASCII `alphanum_word_start`/`alphanum_word_end` boundaries even in
# the Unicode layer, so `bob@example.com中` still yields `bob@example.com` in
# both modes — Unicode mode never *removes* an email/URL/XMPP match that ASCII
# mode finds. Also deliberate; pinned by the same test. Local parts stay
# ASCII, matching the email/XMPP local-part grammars (which parse_unicode_iocs
# leaves untouched). See ioc_grammars._build_domain_layer for the
# corresponding grammar change.
_DOMAIN_CANDIDATE_RE_UNICODE = re.compile(
    r"(?<![^\W_])"
    r"\w[\w-]{0,62}"
    r"(?:\.\w[\w-]{0,62})+"
    r"(?![^\W_])"
)
# Email local part stays ASCII (`_EMAIL_LOCAL_CHARS`); only the domain tail
# widens to the Unicode label class `[\w.\-]` (`\w` == `str.isalnum()` + '_').
_EMAIL_DOMAIN_TAIL_RE_UNICODE = re.compile(r"\[[^\]\s]{1,80}\]|[\w.\-]+")
_XMPP_CANDIDATE_RE_UNICODE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"[A-Za-z0-9][A-Za-z0-9+\-_.]*"
    r"@"
    r"[\w.\-]*?(?i:jabber|xmpp)[\w.\-]*"
)

# Bitcoin-address candidates: mirrors the three Regex() branches in the
# grammar — P2PKH ("1…"), P2SH ("3…"), and Bech32 ("bc1…", lowercase).
# Boundaries match alphanum_word_start / alphanum_word_end.
_BITCOIN_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:[13][A-Za-z0-9]{25,34}|bc1[A-Za-z0-9]{11,71})"
    r"(?![A-Za-z0-9])"
)

# IPv4 CIDR candidates: an IPv4-shaped run + '/' + 1–2 digits. Boundaries
# match the ipv4 prefilter (alphanum_word_start excluding leading '.' too)
# and alphanum_word_end. Per-octet `<256` and the bit-range bounds are
# still enforced by the grammar.
# `[0-9]`, not `\d`, for the same reason as _IPV4_CANDIDATE_RE: the grammar's
# ASCII-only Word(nums) no longer backstops these spans, and the bit range is
# emitted verbatim — a Unicode-aware `\d` would let non-ASCII digits through.
# The Unicode-aware `(?<!\d)` matches _IPV4_CANDIDATE_RE (see the comment
# there); no trailing `(?!\d)` on the bit range because the grammar's
# `Word(nums, max=2)` was not a keyword — it truncated before a non-ASCII
# digit ("1.2.3.4/1٣" -> "1.2.3.4/1") rather than rejecting, and the
# `(?![A-Za-z0-9])` lookahead reproduces exactly that.
_IPV4_CIDR_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9.])(?<!\d)(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}(?![A-Za-z0-9])")

# IPv6 CIDR candidates: hex+colon runs that contain at least two colons,
# followed by '/' and 1-3 digit bit-range. Same boundary shape as the IPv6
# address prefilter; the bit-range is validated against 0..128 by the
# Python validator below (which also reuses `_is_valid_ipv6` so the same
# shortened/`::`/trailing-`::` forms the address parser accepts are also
# accepted here). See https://github.com/fhightower/ioc-finder/issues/121.
#
# The lookbehind also rejects starts right after `]` or `)` (defang close
# brackets) so partially-defanged inputs like `2001[:]db8::/32` or
# `2001(:)db8::/32` do not partial-match as a truncated `db8::/32`. Fully
# refanging those forms would require running the validator against the
# post-fang text, which has its own quirks; this narrow boundary fix is
# enough to keep the partial-host truncation from surfacing.
#
# The bit range is `[0-9]`, not `\d`: this parser is pure-Python (no grammar
# backstop) and `str.isdigit()` in the validator accepts non-ASCII digits, so
# a Unicode-aware `\d` would emit CIDRs like "2001:db8::/٣٢" verbatim.
_IPV6_CIDR_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9:\])])(?:[0-9A-Fa-f]*:){2,}[0-9A-Fa-f]*/[0-9]{1,3}(?![A-Za-z0-9])")

# Socket address candidates: either a dotted IPv4 quad or a bracketed IPv6
# literal, followed by ':' and a 1..5 digit port. Boundaries reject hugging
# alphanumerics so e.g. `5.1.2.3.4:80` cannot tail-match `1.2.3.4:80`. The
# numeric port range, octet ranges, and IPv6 shape are validated by the
# Python validator below; the prefilter is intentionally a superset.
# See https://github.com/fhightower/ioc-finder/issues/248.
#
# Digits are `[0-9]`, not `\d`: this parser is pure-Python (no grammar
# backstop) and the validator's `str.isdigit()`/`int()` accept non-ASCII
# digits, so a Unicode-aware `\d` would emit sockets like "١.٢.٣.٤:80" or
# "1.2.3.4:٨0" verbatim.
_SOCKET_ADDRESS_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9.])"
    r"(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|\[[0-9A-Fa-f:]+\])"
    r":[0-9]{1,5}"
    r"(?![A-Za-z0-9])"
)

# Google AdSense publisher-id candidates: `pub-` or `PUB-` (the grammar uses
# `one_of("pub- PUB-")`, so mixed case is rejected) + exactly 16 digits.
_GOOGLE_ADSENSE_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])(?:pub-|PUB-)\d{16}(?![A-Za-z0-9])")

# Google Analytics tracker-id candidates: `ua-` or `UA-` (grammar uses
# `one_of("ua- UA-")`) + 6+ digit account + `-` + digit property.
_GOOGLE_ANALYTICS_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])(?:ua-|UA-)\d{6,}-\d+(?![A-Za-z0-9])")

# ssdeep candidates: `<chunksize>:<chunk>:<double_chunk>` where chunk and
# double_chunk are runs of alphanums + '/+' (each min length 3 in the
# grammar). The grammar's add_condition checks `len(chunk) >= len(double)`,
# which the prefilter doesn't replicate — false positives are rejected by
# the grammar. Boundary mirrors alphanum_word_start.
_SSDEEP_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])\d+:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}")

# Monero-address candidates: the grammar's regex is
# `4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}` with alphanum boundaries. The body
# alphabet excludes '0', 'I', 'O', 'l' (Base58).
_MONERO_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?![A-Za-z0-9])")

# File-path candidates: the file_path grammar accepts either a Windows path
# (drive letter + ':' + dotless body + '.' + 1–5 letter extension) or a Unix
# path (starting '~' or '/', same body+extension shape, with a "//" not in
# tokens[0] post-condition the grammar enforces). The body uses
# Word(printables + ' ', exclude_chars='.') — printable chars including
# spaces but no dots — so dotless tokens may be separated by runs of
# spaces/tabs (the grammar's body word matches multi-space runs too, e.g.
# "C:\Program  Files\app.exe"). Newlines are excluded from inter-token
# separators because the grammar's printables don't include them.
_FILE_PATH_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:"
    r"[A-Za-z0-9]:[^\s.]+(?:[ \t]+[^\s.]+)*\.[A-Za-z]{1,5}"
    r"|"
    r"[~/][^\s.]+(?:[ \t]+[^\s.]+)*\.[A-Za-z]{1,5}"
    r")"
    r"(?![A-Za-z0-9])"
)

IndicatorList = list[str]
IndicatorDict = dict[str, IndicatorList]
# using `Mapping` b/c it is covariant (https://mypy.readthedocs.io/en/stable/generics.html#variance-of-generic-types)
IndicatorData = Mapping[str, IndicatorList | IndicatorDict]

SUPPORTED_IOC_TYPES = [
    "asns",
    "attack_mitigations",
    "attack_tactics",
    "attack_techniques",
    "authentihashes",
    "bitcoin_addresses",
    "cves",
    "domains",
    "email_addresses",
    "email_addresses_complete",
    "file_paths",
    "google_adsense_publisher_ids",
    "google_analytics_tracker_ids",
    "imphashes",
    "ipv4_cidrs",
    "ipv4s",
    "ipv6_cidrs",
    "ipv6s",
    "mac_addresses",
    "md5s",
    "monero_addresses",
    "registry_key_paths",
    "sha1s",
    "sha256s",
    "sha512s",
    "socket_addresses",
    "ssdeeps",
    "tlp_labels",
    "urls",
    "urls_complete",
    "user_agents",
    "xmpp_addresses",
]

DEFAULT_IOC_TYPES = [
    "cves",
    "domains",
    "email_addresses",
    "ipv4s",
    "ipv6s",
    "md5s",
    "sha1s",
    "sha256s",
    "urls",
]


def _deduplicate(indicator_list: Iterable) -> list:
    """Deduplicate the list of observables."""
    return list(set(indicator_list))


def _remove_items(items: list[str], text: str) -> str:
    """Remove each item from the text."""
    for item in items:
        text = text.replace(item, " ")
    return text


def _get_items(
    iocs: IndicatorData,
    key: str,
    func_if_none: Callable[[str], IndicatorList],
    text: str,
    **kwargs,
) -> IndicatorList:
    data: IndicatorList = iocs.get(key)  # type: ignore
    if data is None:
        data = func_if_none(text, **kwargs)
    return data


def prepare_text(text: str) -> str:
    """Prepare the text for parsing.

    Currently, this involves fanging (https://ioc-fang.hightower.space/) the text."""
    fanged = ioc_fanger.fang(text)
    if logger.isEnabledFor(logging.DEBUG) and fanged != text:
        logger.debug("prepare_text fanged the input (length=%d)", len(text))
    # text = text.encode('idna').decode('utf-8')
    return fanged


def _clean_url(url: str) -> str:
    """Clean the given URL, removing common, unwanted characters which are usually not part of the URL."""
    original = url
    # if there is a ")" in the URL and not a "(", remove everything including and after the ")"
    if ")" in url and "(" not in url:
        url = url.split(")")[0]

    # remove `"` and `'` characters from the end of a URL
    url = url.rstrip('"').rstrip("'")

    # remove `'/>` and `"/>` from the end of a URL (this character string occurs at the end of an HMTL tag with )
    url = url.removesuffix("'/>")
    url = url.removesuffix('"/>')

    if url != original:
        logger.debug("_clean_url trimmed %r -> %r", original, url)
    return url


def _domain_grammars(parse_unicode_iocs: bool):
    """Return the namespace of domain/email/URL/XMPP grammars to use: the
    module-level ASCII grammars (``ioc_grammars``) or, when ``parse_unicode_iocs``
    is set, the Unicode-aware layer from ``ioc_grammars.unicode_domain_layer()``.
    Both expose the same attribute names (``domain_name``, ``email_address``,
    ``scheme_less_url``, ...)."""
    return ioc_grammars.unicode_domain_layer() if parse_unicode_iocs else ioc_grammars


def parse_urls(text: str, *, parse_urls_without_scheme: bool = True, parse_unicode_iocs: bool = False) -> list:
    """."""
    grammars = _domain_grammars(parse_unicode_iocs)
    raw_urls, scheme_ful_spans = _scan_url_candidates_with_spans(text, grammars.url)
    raw_urls = list(raw_urls)
    if parse_urls_without_scheme:
        # Blank the exact spans the scheme-ful URLs occupy so the scheme-less
        # grammar can't re-discover their authority/path/query as a second URL.
        masked = _mask_spans(text, scheme_ful_spans)
        raw_urls.extend(_scan_url_candidates(masked, grammars.scheme_less_url))
    # Cleaning may collapse two raw matches to the same string, so dedupe again.
    return _deduplicate(map(_clean_url, raw_urls))


def parse_urls_complete(text: str, *, parse_urls_without_scheme: bool = True, parse_unicode_iocs: bool = False) -> list:
    """."""
    grammars = _domain_grammars(parse_unicode_iocs)
    raw_urls, scheme_ful_spans = _scan_url_candidates_with_spans(text, grammars.url_complete)
    raw_urls = list(raw_urls)
    if parse_urls_without_scheme:
        masked = _mask_spans(text, scheme_ful_spans)
        raw_urls.extend(_scan_url_candidates(masked, grammars.scheme_less_url_complete))
    return _deduplicate(map(_clean_url, raw_urls))


def _parse_url(url: str, *, parse_unicode_iocs: bool = False) -> ParseResults:
    """Parse a URL by trying the four URL grammars in order, since each may match
    a different shape of input (scheme-ful vs scheme-less, narrow vs complete)."""
    grammars = _domain_grammars(parse_unicode_iocs)
    for grammar in (
        grammars.url,
        grammars.scheme_less_url,
        grammars.url_complete,
        grammars.scheme_less_url_complete,
    ):
        try:
            return grammar.parse_string(url)
        except ParseException:
            continue
    raise ParseException(url, msg=f"could not parse URL: {url!r}")


def _remove_url_domain_name(urls: list, text: str, *, parse_unicode_iocs: bool = False) -> str:
    """Remove the domain name of each url from the text."""
    for url in urls:
        parsed_url = _parse_url(url, parse_unicode_iocs=parse_unicode_iocs)
        url_authority = parsed_url.url_authority
        if isinstance(url_authority, ParseResults):
            url_authority = url_authority[0]
        text = text.replace(url_authority, " ")
    return text


def _remove_url_paths(urls: list, text: str, *, parse_unicode_iocs: bool = False) -> str:
    """Remove the path of each url from the text."""
    for url in urls:
        parsed_url = _parse_url(url, parse_unicode_iocs=parse_unicode_iocs)
        url_path = urlparse.unquote_plus(parsed_url.url_path)

        is_cidr_range = parse_ipv4_cidrs(str(url))
        # if the 'url' has a URL path and is not a cidr range, remove the url_path
        if not is_cidr_range and len(url_path) > 1:
            text = text.replace(url_path, " ")
    return text


def _remove_url_userinfo(urls: list, text: str, *, parse_unicode_iocs: bool = False) -> str:
    """Remove userinfo from each URL so it is not parsed as an email address."""
    grammars = _domain_grammars(parse_unicode_iocs)
    for url in urls:
        # Only the "complete" grammars expose url_userinfo. Try both because
        # `scheme_less_url_complete` now rejects scheme-ful URLs.
        for grammar in (grammars.url_complete, grammars.scheme_less_url_complete):
            try:
                parsed_url = grammar.parse_string(url)
                break
            except ParseException:
                continue
        else:
            continue
        userinfo = parsed_url.url_authority.get("url_userinfo")
        if userinfo:
            text = text.replace(f"{userinfo}@", " ")
    return text


def _percent_decode_url(urls: list, text: str) -> str:
    for url in urls:
        text = text.replace(url, urlparse.unquote_plus(url))
    return text


def parse_domain_names(text, *, parse_unicode_iocs: bool = False):
    """."""
    candidate_re = _DOMAIN_CANDIDATE_RE_UNICODE if parse_unicode_iocs else _DOMAIN_CANDIDATE_RE
    seen: set[str] = set()
    out: list[str] = []
    for m in candidate_re.finditer(text):
        candidate = m.group(0).lower()
        segments = candidate.split(".")
        # Walk segments right-to-left for the rightmost TLD that still
        # leaves ≥1 preceding label. Mirrors how `domain_name`'s
        # OneOrMore(label + ".") + domain_tld backtracks to land on the
        # longest valid `…labels.tld` — e.g. "foo.com.invalid" → "foo.com",
        # "192.168.1.1" → no match, "gmail.com.zip" → "gmail.com.zip".
        # Assumes every entry in `ioc_grammars.TLD_SET` is a single label. If `tlds`
        # is ever replaced by a Public Suffix List (which contains multi-
        # label suffixes like "co.uk"), this single-segment lookup will
        # miss them and the walk needs to grow a multi-segment probe.
        tld_idx = -1
        for i in range(len(segments) - 1, 0, -1):
            if segments[i] in ioc_grammars.TLD_SET:
                tld_idx = i
                break
        if tld_idx < 1:
            continue
        domain = ".".join(segments[: tld_idx + 1])
        if domain not in seen:
            seen.add(domain)
            out.append(domain)
    return out


def _normalized_ipv4(span: str) -> str | None:
    """Validate and normalize an IPv4 candidate span in pure Python, mirroring
    ioc_grammars.ipv4_address: every octet must be < 256, and each is passed
    through int() so leading zeros are stripped exactly like the grammar's
    `str(int(...))` parse action ("001.002.003.004" -> "1.2.3.4"). The
    candidate regexes guarantee four 1-3 digit groups and enforce the word
    boundaries, so neither is re-checked here."""
    octets = [int(octet) for octet in span.split(".")]
    if any(octet > 255 for octet in octets):
        return None
    return ".".join(map(str, octets))


def _scan_transformed(text, candidate_re, transform: Callable[[str], str | None]) -> list[str]:
    """Run `transform` on each span matched by `candidate_re`, keeping the
    first-seen order of the non-None results and deduplicating on the
    *transformed* value (so e.g. "1.2.3.4" and "01.2.3.4" are one result).
    This is the shared shape of every pure-Python fast path that bypasses
    pyparsing; `transform` returns the parsed value or None to reject."""
    seen: set[str] = set()
    out: list[str] = []
    for m in candidate_re.finditer(text):
        value = transform(m.group(0))
        if value is not None and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def parse_ipv4_addresses(text):
    """."""
    # Pure-Python fast path (see _scan_transformed): the ipv4_address
    # grammar's only transformation is the per-octet normalization
    # reproduced by _normalized_ipv4, so skipping pyparsing preserves the
    # output shape.
    return _scan_transformed(text, _IPV4_CANDIDATE_RE, _normalized_ipv4)


def _scan_candidates(text, candidate_re, grammar):
    """Run `grammar.scan_string` only on the spans matched by `candidate_re`,
    deduplicating tokens[0] across spans. Used by hotspot helpers where the
    pyparsing grammar would otherwise be tried at every offset of the input."""
    seen: set[str] = set()
    out: list[str] = []
    for m in candidate_re.finditer(text):
        for tokens, _start, _end in grammar.scan_string(m.group(0)):
            value = tokens[0]
            if value and value not in seen:
                seen.add(value)
                out.append(value)
    return out


def _email_candidate_spans(text: str, *, parse_unicode_iocs: bool = False) -> Iterator[str]:
    """Yield each plausible email candidate substring by anchoring on '@' and
    expanding outward, instead of letting a `(?:local+)@domain` regex search go
    O(n²) on a long run of local-part characters that never reaches an '@' (e.g.
    a base64/hex blob). Mirrors the marker-expansion approach of
    `_url_candidate_spans`; the email grammar stays the precise validator, so
    each span only needs to be a superset of what the grammar accepts.

    Tracks the old `_EMAIL_CANDIDATE_RE.finditer` scanning order: matches are
    non-overlapping and left-to-right (`search_pos` floors both the '@' scan and
    the leftward local-part expansion onto already-consumed text), a '@'
    preceded by '\\' is an escaped at-sign that belongs to the local part rather
    than a separator, and the domain tail is matched with the same alternation
    the old regex used. The candidate spans are not byte-for-byte identical to
    the old regex in cases the grammar rejects anyway (e.g. a bare leading
    '\\@'), but `find_iocs` detection results are unchanged — verified by an
    order-sensitive equivalence check over the test corpus."""
    tail_re = _EMAIL_DOMAIN_TAIL_RE_UNICODE if parse_unicode_iocs else _EMAIL_DOMAIN_TAIL_RE
    local = _EMAIL_LOCAL_CHARS
    search_pos = 0
    for m in re.finditer("@", text):
        at = m.start()
        if at < search_pos:
            continue
        if at > 0 and text[at - 1] == "\\":  # escaped '@' is local-part, not a separator
            continue
        tail = tail_re.match(text, at + 1)
        if tail is None:
            continue
        start = at
        while start > search_pos:
            char = text[start - 1]
            if char in local:
                start -= 1
            elif char == "@" and start - 2 >= search_pos and text[start - 2] == "\\":
                start -= 2  # step over a `\@` unit embedded in the local part
            else:
                break
        if start == at:  # no local part before the '@'
            continue
        search_pos = tail.end()
        yield text[start : tail.end()]


def _scan_email_candidates(text, grammar, *, parse_unicode_iocs=False):
    """Like `_scan_candidates`, but locates email spans via
    `_email_candidate_spans` (O(n)) rather than a quadratic candidate regex."""
    seen: set[str] = set()
    out: list[str] = []
    for span in _email_candidate_spans(text, parse_unicode_iocs=parse_unicode_iocs):
        for tokens, _start, _end in grammar.scan_string(span):
            value = tokens[0]
            if value and value not in seen:
                seen.add(value)
                out.append(value)
    return out


def _url_candidate_spans(text):
    """Yield `(offset, substring)` for each non-whitespace run around a
    `_URL_MARKER_RE` hit, where `offset` is the run's start index in `text`.
    Built in Python instead of as `\\S*<marker>\\S*` so a long non-whitespace
    run that contains no marker (e.g. a 10kB base64 blob) doesn't trigger
    O(n²) regex backtracking."""
    seen_spans: set[tuple[int, int]] = set()
    n = len(text)
    last_span_end = -1
    for m in _URL_MARKER_RE.finditer(text):
        if m.start() < last_span_end:
            continue
        start = m.start()
        while start > 0 and not text[start - 1].isspace():
            start -= 1
        end = m.end()
        while end < n and not text[end].isspace():
            end += 1
        span = (start, end)
        if span not in seen_spans:
            seen_spans.add(span)
            last_span_end = end
            yield start, text[start:end]


def _scan_url_candidates_with_spans(text, grammar):
    """Run `grammar.scan_string` over each URL candidate span, returning both
    the deduplicated match values and the absolute `(start, end)` character
    spans every raw match occupies in `text`. The spans let callers mask the
    exact regions a scheme-ful URL covers (rather than `str.replace`-ing the
    match text, which blows holes in a longer URL whose substring equals a
    shorter match elsewhere)."""
    seen: set[str] = set()
    out: list[str] = []
    spans: list[tuple[int, int]] = []
    for offset, span in _url_candidate_spans(text):
        for tokens, sub_start, sub_end in grammar.scan_string(span):
            spans.append((offset + sub_start, offset + sub_end))
            value = tokens[0]
            if value and value not in seen:
                seen.add(value)
                out.append(value)
    return out, spans


def _scan_url_candidates(text, grammar):
    values, _spans = _scan_url_candidates_with_spans(text, grammar)
    return values


def _mask_spans(text: str, spans: list[tuple[int, int]]) -> str:
    """Return `text` with every `(start, end)` character range blanked to
    spaces. Same-length replacement keeps all other offsets stable."""
    if not spans:
        return text
    chars = list(text)
    for start, end in spans:
        for i in range(start, min(end, len(chars))):
            chars[i] = " "
    return "".join(chars)


_IPV6_HEXNUMS = frozenset(hexdigits)


def _is_valid_ipv6(s: str) -> bool:
    """Approximate ioc_grammars.ipv6_address structural validation in pure Python.
    The grammar does no transformation (no parse actions on hexadectet / Combine),
    so the output shape matches; the candidate regex already enforces
    ipv6_word_start/end, so boundary checks aren't repeated here.

    Diverges from the old grammar by accepting the unspecified address `::` and
    trailing-`::` forms like `1::` (which the grammar's ipv6_address_shortened
    rejected because it required a trailing hexadectet). Both are valid IPv6,
    so this is a deliberate fix rather than a regression."""
    if s.count(":") < 2:
        return False
    halves = s.split("::")
    if len(halves) > 2:
        return False
    if len(halves) == 2:
        left, right = halves
        left_groups = left.split(":") if left else []
        right_groups = right.split(":") if right else []
        groups = left_groups + right_groups
        if len(groups) > 7:
            return False
    else:
        groups = s.split(":")
        if len(groups) != 8:
            return False
    for g in groups:
        if not (1 <= len(g) <= 4):
            return False
        if not all(c in _IPV6_HEXNUMS for c in g):
            return False
    return True


def parse_ipv6_addresses(text):
    """."""
    # Pure-Python fast path (see _scan_transformed): candidates are
    # validated via _is_valid_ipv6 instead of _scan_candidates + a pyparsing
    # grammar. The grammar applies no parse actions to ipv6_address, so
    # skipping it preserves the output shape.
    return _scan_validated(text, _IPV6_CANDIDATE_RE, _is_valid_ipv6)


def _is_valid_ipv4_quad(host: str) -> bool:
    """Plain-Python IPv4 quad validation that, unlike `ipv4_address`, returns
    the host text unchanged (no leading-zero normalization). Used by
    parse_socket_addresses so observed text like `001.002.003.004:80` is
    preserved verbatim."""
    parts = host.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        if not 0 <= int(p) <= 255:
            return False
    return True


def _is_valid_socket_address(span: str) -> bool:
    """Validate a `host:port` span. Host is either an IPv4 quad or a bracketed
    IPv6 literal; port is 1..65535 (port 0 is reserved by IANA and excluded
    on purpose). Bracketed IPv6 reuses `_is_valid_ipv6` so the same
    shortened/`::`/trailing-`::` forms accepted by `parse_ipv6_addresses` work
    here too."""
    host, _, port = span.rpartition(":")
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        return False
    if host.startswith("[") and host.endswith("]"):
        return _is_valid_ipv6(host[1:-1])
    return _is_valid_ipv4_quad(host)


def parse_socket_addresses(text):
    """."""
    return _scan_validated(text, _SOCKET_ADDRESS_CANDIDATE_RE, _is_valid_socket_address)


def _scan_validated(text, candidate_re, validator):
    """Like _scan_candidates, but uses a pure-Python validator on the matched
    span instead of running a pyparsing grammar. Used where the grammar adds
    no transformation and a hand-written check is faster."""
    return _scan_transformed(text, candidate_re, lambda span: span if validator(span) else None)


def parse_complete_email_addresses(text: str, *, parse_unicode_iocs: bool = False) -> list:
    """."""
    grammar = _domain_grammars(parse_unicode_iocs).complete_email_address
    return _scan_email_candidates(text, grammar, parse_unicode_iocs=parse_unicode_iocs)


def parse_email_addresses(text: str, *, parse_unicode_iocs: bool = False) -> list:
    """."""
    grammar = _domain_grammars(parse_unicode_iocs).email_address
    return _scan_email_candidates(text, grammar, parse_unicode_iocs=parse_unicode_iocs)


# there is a trailing underscore on this function to differentiate it from the argument with the same name
def parse_imphashes_(text: str) -> list:
    """."""
    full_imphash_instances = _scan_candidates(text.lower(), _IMPHASH_CANDIDATE_RE, ioc_grammars.imphash)

    return _deduplicate(ioc_grammars.imphash.parse_string(imphash).hash[0] for imphash in full_imphash_instances)


# there is a trailing underscore on this function to differentiate it from the argument with the same name
def parse_authentihashes_(text: str) -> list:
    """."""
    full_authentihash_instances = _scan_candidates(text.lower(), _AUTHENTIHASH_CANDIDATE_RE, ioc_grammars.authentihash)

    return _deduplicate(ioc_grammars.authentihash.parse_string(a).hash[0] for a in full_authentihash_instances)


def _scan_hash_candidates(text, candidate_re):
    """Pure-Python fast path for the fixed-length hex hash types. Unlike the
    other candidate regexes (which are deliberate supersets of their grammars),
    the md5/sha1/sha256/sha512 candidate regexes are *exact* mirrors: same hex
    charset, exact length, same word-boundary rules — and the grammars' only
    parse action is downcasing. So the lowercased regex match IS the grammar
    output and pyparsing can be skipped entirely. If a hash grammar in
    ioc_grammars ever grows a rule its candidate regex doesn't mirror, these
    parsers must go back through _scan_candidates. (parse_imphashes_ /
    parse_authentihashes_ still run the real imphash/authentihash grammars,
    which embed md5/sha256.) The regex/grammar equivalence is asserted by
    tests/test_fast_path_equivalence.py."""
    return _scan_transformed(text, candidate_re, str.lower)


def parse_md5s(text):
    """."""
    return _scan_hash_candidates(text, _MD5_CANDIDATE_RE)


def parse_sha1s(text):
    """."""
    return _scan_hash_candidates(text, _SHA1_CANDIDATE_RE)


def parse_sha256s(text):
    """."""
    return _scan_hash_candidates(text, _SHA256_CANDIDATE_RE)


def parse_sha512s(text):
    """."""
    return _scan_hash_candidates(text, _SHA512_CANDIDATE_RE)


def parse_ssdeeps(text):
    """."""
    return _scan_candidates(text, _SSDEEP_CANDIDATE_RE, ioc_grammars.ssdeep)


def parse_asns(text):
    """."""
    return _scan_candidates(text, _ASN_CANDIDATE_RE, ioc_grammars.asn)


def parse_cves(text):
    """."""
    return _scan_candidates(text, _CVE_CANDIDATE_RE, ioc_grammars.cve)


def _normalized_ipv4_cidr(span: str) -> str | None:
    """Transform for the ipv4_cidr fast path: the address half gets the same
    per-octet <256 check and leading-zero normalization as
    parse_ipv4_addresses (via _normalized_ipv4); the bit range is kept
    verbatim. The grammar's `Word(nums, max=2)` put no numeric bound on the
    bit range (so e.g. "/99" was accepted), and the candidate regex's
    `/[0-9]{1,2}` reproduces that — deliberately unchanged here."""
    address, _, bits = span.partition("/")
    normalized = _normalized_ipv4(address)
    if normalized is None:
        return None
    return f"{normalized}/{bits}"


def parse_ipv4_cidrs(text: str) -> list:
    """."""
    return _scan_transformed(text, _IPV4_CIDR_CANDIDATE_RE, _normalized_ipv4_cidr)


def _is_valid_ipv6_cidr(span: str) -> bool:
    """Validate an IPv6 CIDR span. Reuses `_is_valid_ipv6` for the address half
    so the same shortened/`::`/trailing-`::` forms accepted by
    `parse_ipv6_addresses` are also accepted here (the strict `ipv6_address`
    grammar would reject `::/0` and `1::/64`)."""
    addr, _, bits = span.rpartition("/")
    if not bits.isdigit():
        return False
    if not 0 <= int(bits) <= 128:
        return False
    return _is_valid_ipv6(addr)


def parse_ipv6_cidrs(text: str) -> list:
    """."""
    return _scan_validated(text, _IPV6_CIDR_CANDIDATE_RE, _is_valid_ipv6_cidr)


def parse_registry_key_paths(text):
    """."""
    full_parsed_registry_key_paths = _scan_candidates(text, _REGISTRY_KEY_CANDIDATE_RE, ioc_grammars.registry_key_path)

    registry_key_paths = []
    for registry_key_path in full_parsed_registry_key_paths:
        # if there is a space in the last section of the parsed registry key path,
        # remove it so that content after a registry key path is not also pulled in...
        # this is a limitation of the grammar:
        # it will not parse a registry key path with a space in the final section (the section after the final '\')
        if " " in registry_key_path.split("\\")[-1]:
            last_section = registry_key_path.split("\\")[-1]
            registry_key_path = registry_key_path.replace(last_section, last_section.split(" ")[0])
            registry_key_paths.append(registry_key_path)
        else:
            registry_key_paths.append(registry_key_path)

    return registry_key_paths


def parse_google_adsense_ids(text):
    """."""
    return _scan_candidates(text, _GOOGLE_ADSENSE_CANDIDATE_RE, ioc_grammars.google_adsense_publisher_id)


def parse_google_analytics_ids(text):
    """."""
    return _scan_candidates(text, _GOOGLE_ANALYTICS_CANDIDATE_RE, ioc_grammars.google_analytics_tracker_id)


def parse_bitcoin_addresses(text):
    """."""
    return _scan_candidates(text, _BITCOIN_CANDIDATE_RE, ioc_grammars.bitcoin_address)


def parse_monero_addresses(text):
    """."""
    return _scan_candidates(text, _MONERO_CANDIDATE_RE, ioc_grammars.monero_address)


def parse_xmpp_addresses(text: str, *, parse_unicode_iocs: bool = False) -> list:
    """."""
    candidate_re = _XMPP_CANDIDATE_RE_UNICODE if parse_unicode_iocs else _XMPP_CANDIDATE_RE
    return _scan_candidates(text, candidate_re, _domain_grammars(parse_unicode_iocs).xmpp_address)


def _remove_xmpp_local_part(xmpp_addresses: list, text: str) -> str:
    """Remove the local part of each xmpp_address from the text."""
    for address in xmpp_addresses:
        text = text.replace(address.split("@")[0] + "@", " ")

    return text


def parse_mac_addresses(text):
    """."""
    return _scan_candidates(text, _MAC_CANDIDATE_RE, ioc_grammars.mac_address)


def parse_user_agents(text):
    """."""
    # User-agent strings can contain almost any printable char, so we can't
    # build a candidate regex that captures the whole UA up front. Instead,
    # find each `[Mm]ozilla/<digit>` start and run the grammar on the slice
    # from that start to the next start (or end of text). That keeps two
    # concatenated UAs on the same line as separate spans, which the grammar
    # otherwise has trouble splitting because Combine(...adjacent=False) will
    # happily merge them.
    starts = [m.start() for m in _USER_AGENT_START_RE.finditer(text)]
    if not starts:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(text)
        for tokens, _s, _e in ioc_grammars.user_agent.scan_string(text[start:end]):
            value = tokens[0]
            if value and value not in seen:
                seen.add(value)
                out.append(value)
    return out


def parse_file_paths(text):
    """."""
    return _scan_candidates(text, _FILE_PATH_CANDIDATE_RE, ioc_grammars.file_path)


def parse_pre_attack_tactics(text):
    """."""
    return _scan_candidates(text, _ATTACK_TACTIC_CANDIDATE_RE, ioc_grammars.pre_attack_tactics_grammar)


def parse_pre_attack_techniques(text):
    """."""
    return _scan_candidates(text, _ATTACK_TECHNIQUE_CANDIDATE_RE, ioc_grammars.pre_attack_techniques_grammar)


def parse_enterprise_attack_mitigations(text):
    """."""
    return _scan_candidates(text, _ATTACK_MITIGATION_CANDIDATE_RE, ioc_grammars.enterprise_attack_mitigations_grammar)


def parse_enterprise_attack_tactics(text):
    """."""
    return _scan_candidates(text, _ATTACK_TACTIC_CANDIDATE_RE, ioc_grammars.enterprise_attack_tactics_grammar)


def parse_enterprise_attack_techniques(text):
    """."""
    return _scan_candidates(text, _ATTACK_TECHNIQUE_CANDIDATE_RE, ioc_grammars.enterprise_attack_techniques_grammar)


def parse_mobile_attack_mitigations(text):
    """."""
    return _scan_candidates(text, _ATTACK_MITIGATION_CANDIDATE_RE, ioc_grammars.mobile_attack_mitigations_grammar)


def parse_mobile_attack_tactics(text):
    """."""
    return _scan_candidates(text, _ATTACK_TACTIC_CANDIDATE_RE, ioc_grammars.mobile_attack_tactics_grammar)


def parse_mobile_attack_techniques(text):
    """."""
    return _scan_candidates(text, _ATTACK_TECHNIQUE_CANDIDATE_RE, ioc_grammars.mobile_attack_techniques_grammar)


def parse_tlp_labels(text):
    """."""
    return _scan_candidates(text, _TLP_CANDIDATE_RE, ioc_grammars.tlp_label)


@click.command()
@click.argument("text", required=False)
@click.option(
    "--no_url_domain_parsing",
    is_flag=True,
    help="Using this flag will not parse domain names from URLs",
)
@click.option(
    "--no_parse_from_url_path",
    is_flag=True,
    help="Using this flag will not parse observables from URL paths",
)
@click.option(
    "--no_email_addr_domain_parsing",
    is_flag=True,
    help="Using this flag will not parse domain names from email addresses",
)
@click.option(
    "--no_cidr_address_parsing",
    is_flag=True,
    help="Using this flag will not parse IP addresses from CIDR ranges",
)
@click.option(
    "--no_xmpp_addr_domain_parsing",
    is_flag=True,
    help="Using this flag will not parse domain names from XMPP addresses",
)  # pylint: disable=R0913
@click.option(
    "--parse_urls_without_scheme",
    is_flag=True,
    help="Using this flag will parse URLs with and without a scheme (default is True)",
    default=True,
)
@click.option(
    "--parse_unicode_iocs",
    is_flag=True,
    help="Allow non-ASCII (Unicode) characters in domain labels (and the domain part of email/URL/XMPP IOCs)",
)
@click.option(
    "--all",
    "parse_all",
    is_flag=True,
    help="Parse every supported indicator type instead of the common defaults.",
)
def cli_find_iocs(
    text,
    no_url_domain_parsing,
    no_parse_from_url_path,
    no_email_addr_domain_parsing,
    no_cidr_address_parsing,
    no_xmpp_addr_domain_parsing,
    parse_urls_without_scheme,
    parse_unicode_iocs,
    parse_all,
):
    """CLI interface for parsing observables."""
    stdin_text = click.get_text_stream("stdin")

    # if there is stdin, use it
    if not text and stdin_text:
        text = "\n".join(stdin_text)
        # text = '\n'.join([line for line in stdin_text])

    included_ioc_types = list(SUPPORTED_IOC_TYPES if parse_all else DEFAULT_IOC_TYPES)
    iocs = find_iocs(
        text,
        parse_domain_from_url=not no_url_domain_parsing,
        parse_from_url_path=not no_parse_from_url_path,
        parse_domain_from_email_address=not no_email_addr_domain_parsing,
        parse_address_from_cidr=not no_cidr_address_parsing,
        parse_domain_name_from_xmpp_address=not no_xmpp_addr_domain_parsing,
        parse_urls_without_scheme=parse_urls_without_scheme,
        parse_unicode_iocs=parse_unicode_iocs,
        included_ioc_types=included_ioc_types,
    )
    ioc_string = json.dumps(iocs, indent=4, sort_keys=True)
    print(ioc_string)


def find_iocs(
    text: str,
    *,
    parse_domain_from_url: bool = True,
    parse_from_url_path: bool = True,
    parse_domain_from_email_address: bool = True,
    parse_address_from_cidr: bool = True,
    parse_domain_name_from_xmpp_address: bool = True,
    parse_urls_without_scheme: bool = True,
    parse_unicode_iocs: bool = False,
    included_ioc_types: Iterable[str] | None = None,
) -> IndicatorData:
    """Find observables (a.k.a. indicators of compromise) in the given text.

    Args:
        text: The text to parse for indicators.
        parse_domain_from_url: Whether to parse domain names from URLs. Only applicable
            when ``"domains"`` is in ``included_ioc_types``.
        parse_from_url_path: Whether to parse observables from URL paths. Only applicable
            when IOC types that could appear in a URL path (e.g. ``"domains"``, hash types)
            are in ``included_ioc_types``.
        parse_domain_from_email_address: Whether to parse domain names from email addresses.
            Only applicable when ``"domains"`` is in ``included_ioc_types``.
        parse_address_from_cidr: Whether to parse IP addresses from CIDR ranges. Only
            applicable when ``"ipv4s"`` is in ``included_ioc_types``.
        parse_domain_name_from_xmpp_address: Whether to parse domain names from XMPP
            addresses. Only applicable when ``"domains"`` is in ``included_ioc_types``.
        parse_urls_without_scheme: Whether to parse URLs without a scheme. Only applicable
            when ``"urls"`` or ``"urls_complete"`` is in ``included_ioc_types``.
        parse_unicode_iocs: Whether to allow non-ASCII (Unicode) characters in domain
            labels. When ``True``, domains like ``warrıors.com`` are parsed (and likewise
            the domain part of email, URL, and XMPP IOCs). Defaults to ``False`` so the
            ASCII-only behaviour is unchanged unless explicitly opted into. The TLD
            itself is always ASCII (IANA stores IDN TLDs in their ``xn--`` punycode
            form), as are email/URL/XMPP local parts and URL paths.
        included_ioc_types: Collection of IOC type names to parse. If ``None``,
            the common default types are parsed (see ``DEFAULT_IOC_TYPES``). For
            the full list of parseable types, see ``SUPPORTED_IOC_TYPES``. When
            specified, the boolean options above only take effect if their
            corresponding IOC type is included.
    """
    if included_ioc_types is None:
        included_ioc_types = DEFAULT_IOC_TYPES

    included_ioc_types = set(included_ioc_types)
    unsupported = included_ioc_types - set(SUPPORTED_IOC_TYPES)
    if unsupported:
        logger.warning(
            "Ignoring unsupported IOC types: %s. Supported types: %s",
            sorted(unsupported),
            SUPPORTED_IOC_TYPES,
        )
        included_ioc_types -= unsupported

    logger.info(
        "find_iocs starting (text_length=%d, ioc_type_count=%d)",
        len(text),
        len(included_ioc_types),
    )
    iocs: dict = {}

    # Stash the pre-fang text. `ioc_fanger.fang` rewrites the `::/` in IPv6 CIDRs
    # to `://` (mistaking it for a defanged scheme separator), which would
    # silently swallow indicators like `2001:db8::/32`. parse_ipv6_cidrs runs
    # against this pre-fang copy so the rewrite cannot destroy the IOC.
    prefang_text = text
    text = prepare_text(text)
    # keep a copy of the original text - some items should be parsed from the original text
    original_text = text

    # urls
    if "urls" in included_ioc_types:
        iocs["urls"] = parse_urls(
            text, parse_urls_without_scheme=parse_urls_without_scheme, parse_unicode_iocs=parse_unicode_iocs
        )

    # urls_complete
    if "urls_complete" in included_ioc_types:
        iocs["urls_complete"] = parse_urls_complete(
            text, parse_urls_without_scheme=parse_urls_without_scheme, parse_unicode_iocs=parse_unicode_iocs
        )

    # TODO: clean this section up
    if not parse_domain_from_url and not parse_from_url_path:
        text = _remove_items(iocs.get("urls", []), text)
        text = _remove_items(iocs.get("urls_complete", []), text)
    elif not parse_domain_from_url:
        text = _percent_decode_url(iocs.get("urls", []), text)
        text = _remove_url_domain_name(iocs.get("urls", []), text, parse_unicode_iocs=parse_unicode_iocs)

        text = _percent_decode_url(iocs.get("urls_complete", []), text)
        text = _remove_url_domain_name(iocs.get("urls_complete", []), text, parse_unicode_iocs=parse_unicode_iocs)
    elif not parse_from_url_path:
        text = _percent_decode_url(iocs.get("urls", []), text)
        text = _remove_url_paths(iocs.get("urls", []), text, parse_unicode_iocs=parse_unicode_iocs)

        text = _percent_decode_url(iocs.get("urls_complete", []), text)
        text = _remove_url_paths(iocs.get("urls_complete", []), text, parse_unicode_iocs=parse_unicode_iocs)
    else:
        text = _percent_decode_url(iocs.get("urls", []), text)
        text = _percent_decode_url(iocs.get("urls_complete", []), text)

    # xmpp addresses
    if "xmpp_addresses" in included_ioc_types:
        iocs["xmpp_addresses"] = parse_xmpp_addresses(text, parse_unicode_iocs=parse_unicode_iocs)

    if "domains" in included_ioc_types and not parse_domain_name_from_xmpp_address:
        xmpp_addresses = _get_items(
            iocs, "xmpp_addresses", parse_xmpp_addresses, text, parse_unicode_iocs=parse_unicode_iocs
        )
        text = _remove_items(xmpp_addresses, text)
    # even if we want to parse domain names from the xmpp_address,
    # we don't want them also being caught as email addresses so we'll remove everything before the `@`
    elif "email_addresses_complete" in included_ioc_types or "email_addresses" in included_ioc_types:
        xmpp_addresses = _get_items(
            iocs, "xmpp_addresses", parse_xmpp_addresses, text, parse_unicode_iocs=parse_unicode_iocs
        )
        text = _remove_xmpp_local_part(xmpp_addresses, text)

    if "email_addresses_complete" in included_ioc_types or "email_addresses" in included_ioc_types:
        text = _remove_url_userinfo(iocs.get("urls_complete", []), text, parse_unicode_iocs=parse_unicode_iocs)

    # complete email addresses
    if "email_addresses_complete" in included_ioc_types:
        iocs["email_addresses_complete"] = parse_complete_email_addresses(text, parse_unicode_iocs=parse_unicode_iocs)
    if "email_addresses" in included_ioc_types:
        iocs["email_addresses"] = parse_email_addresses(text, parse_unicode_iocs=parse_unicode_iocs)

    if not parse_domain_from_email_address:
        email_addresses_complete = _get_items(
            iocs,
            "email_addresses_complete",
            parse_complete_email_addresses,
            text,
            parse_unicode_iocs=parse_unicode_iocs,
        )
        email_addresses = _get_items(
            iocs, "email_addresses", parse_email_addresses, text, parse_unicode_iocs=parse_unicode_iocs
        )

        text = _remove_items(email_addresses_complete, text)
        text = _remove_items(email_addresses, text)

    if "ipv6s" in included_ioc_types:
        # after parsing the email addresses, we need to remove the
        # '[IPv6:' bit from any of the email addresses so that ipv6 addresses are not extraneously parsed
        text = _remove_items(["[IPv6:"], text)

    # cidr ranges
    if "ipv4_cidrs" in included_ioc_types:
        iocs["ipv4_cidrs"] = parse_ipv4_cidrs(text)
    if "ipv6_cidrs" in included_ioc_types:
        # Parse against pre-fang text so the fanger does not eat the `::/` chars.
        iocs["ipv6_cidrs"] = parse_ipv6_cidrs(prefang_text)

    # remove URLs that are also cidr ranges (see https://github.com/fhightower/ioc-finder/issues/91)
    url_parsing_requires_cidr_removal = (
        "urls" in included_ioc_types or "urls_complete" in included_ioc_types
    ) and parse_urls_without_scheme
    ipv4_address_parsing_requires_cidr_removal = "ipv4s" in included_ioc_types and not parse_address_from_cidr
    ipv6_address_parsing_requires_cidr_removal = "ipv6s" in included_ioc_types and not parse_address_from_cidr
    # For ipv6 CIDRs the fang rewrite turns `::/` into `://`, so the address
    # half is no longer present in the post-fang text. When the user wants
    # ipv6 addresses parsed from CIDRs (the default), re-inject the address
    # halves so parse_ipv6_addresses can pick them up.
    ipv6_address_parsing_requires_cidr_reinjection = (
        "ipv6s" in included_ioc_types and "ipv6_cidrs" in included_ioc_types and parse_address_from_cidr
    )
    if (
        url_parsing_requires_cidr_removal
        or ipv4_address_parsing_requires_cidr_removal
        or ipv6_address_parsing_requires_cidr_removal
        or ipv6_address_parsing_requires_cidr_reinjection
    ):
        # Only compute each range list when something below actually consumes it,
        # so we don't pay for an unused parse pass.
        ipv4_cidr_ranges = (
            _get_items(iocs, "ipv4_cidrs", parse_ipv4_cidrs, text)
            if (url_parsing_requires_cidr_removal or ipv4_address_parsing_requires_cidr_removal)
            else []
        )
        ipv6_cidr_ranges = (
            _get_items(iocs, "ipv6_cidrs", parse_ipv6_cidrs, prefang_text)
            if (
                url_parsing_requires_cidr_removal
                or ipv6_address_parsing_requires_cidr_removal
                or ipv6_address_parsing_requires_cidr_reinjection
            )
            else []
        )
        if url_parsing_requires_cidr_removal:
            for cidr in ipv4_cidr_ranges + ipv6_cidr_ranges:
                if cidr in iocs.get("urls", []):
                    iocs["urls"].remove(cidr)
                if cidr in iocs.get("urls_complete", []):
                    iocs["urls_complete"].remove(cidr)
        if ipv4_address_parsing_requires_cidr_removal:
            text = _remove_items(ipv4_cidr_ranges, text)
        if ipv6_address_parsing_requires_cidr_removal:
            text = _remove_items(ipv6_cidr_ranges, text)
        if ipv6_address_parsing_requires_cidr_reinjection:
            # Always append the address half. A substring `in text` guard would
            # incorrectly skip injection when the CIDR base is a *prefix* of an
            # unrelated IPv6 in the same text (e.g. `2001:db8::/32` next to
            # `2001:db8::1234`), causing parse_ipv6_addresses to miss the base.
            # parse_ipv6_addresses deduplicates, so re-injecting an address that
            # also appears as an independent token in `text` is harmless.
            for cidr in ipv6_cidr_ranges:
                addr = cidr.rsplit("/", 1)[0]
                text = f"{text} {addr}"

    # file hashes
    if "imphashes" in included_ioc_types:
        iocs["imphashes"] = parse_imphashes_(text)
    if "md5s" in included_ioc_types:
        # remove the imphashes so they are not also parsed as md5s
        imphashes = _get_items(iocs, "imphashes", parse_imphashes_, text)
        text = _remove_items(imphashes, text)

    if "authentihashes" in included_ioc_types:
        iocs["authentihashes"] = parse_authentihashes_(text)
    if "sha256s" in included_ioc_types:
        # remove the authentihashes so they are not also parsed as sha256s
        authentihashes = _get_items(iocs, "authentihashes", parse_authentihashes_, text)
        text = _remove_items(authentihashes, text)

    # domains
    if "domains" in included_ioc_types:
        iocs["domains"] = parse_domain_names(text, parse_unicode_iocs=parse_unicode_iocs)

    # ip addresses
    if "ipv4s" in included_ioc_types:
        iocs["ipv4s"] = parse_ipv4_addresses(text)
    if "ipv6s" in included_ioc_types:
        iocs["ipv6s"] = parse_ipv6_addresses(text)
    if "socket_addresses" in included_ioc_types:
        # Run alongside the address parsers so a socket like `1.2.3.4:8080`
        # surfaces in addition to its IPv4 half (matching existing CIDR
        # behavior where the address half is also reported by default).
        iocs["socket_addresses"] = parse_socket_addresses(text)

    # file hashes
    if "sha512s" in included_ioc_types:
        iocs["sha512s"] = parse_sha512s(text)
    if "sha256s" in included_ioc_types:
        iocs["sha256s"] = parse_sha256s(text)
    if "sha1s" in included_ioc_types:
        iocs["sha1s"] = parse_sha1s(text)
    if "md5s" in included_ioc_types:
        iocs["md5s"] = parse_md5s(text)
    if "ssdeeps" in included_ioc_types:
        # remove ipv6 addresses so they are not parsed as ssdeep hashes
        # (see https://github.com/fhightower/ioc-finder/issues/228)
        ssdeep_text = text
        ipv6s = _get_items(iocs, "ipv6s", parse_ipv6_addresses, text)
        ssdeep_text = _remove_items(ipv6s, ssdeep_text)
        iocs["ssdeeps"] = parse_ssdeeps(ssdeep_text)

    # misc
    if "asns" in included_ioc_types:
        iocs["asns"] = parse_asns(text)
    if "cves" in included_ioc_types:
        iocs["cves"] = parse_cves(original_text)
    if "registry_key_paths" in included_ioc_types:
        iocs["registry_key_paths"] = parse_registry_key_paths(text)
    if "google_adsense_publisher_ids" in included_ioc_types:
        iocs["google_adsense_publisher_ids"] = parse_google_adsense_ids(text)
    if "google_analytics_tracker_ids" in included_ioc_types:
        iocs["google_analytics_tracker_ids"] = parse_google_analytics_ids(text)
    if "bitcoin_addresses" in included_ioc_types:
        iocs["bitcoin_addresses"] = parse_bitcoin_addresses(text)
    if "monero_addresses" in included_ioc_types:
        iocs["monero_addresses"] = parse_monero_addresses(text)
    if "mac_addresses" in included_ioc_types:
        iocs["mac_addresses"] = parse_mac_addresses(text)
    if "user_agents" in included_ioc_types:
        iocs["user_agents"] = parse_user_agents(text)
    if "tlp_labels" in included_ioc_types:
        iocs["tlp_labels"] = parse_tlp_labels(original_text)

    if "attack_mitigations" in included_ioc_types:
        iocs["attack_mitigations"] = {  # type: ignore
            "enterprise": parse_enterprise_attack_mitigations(original_text),
            "mobile": parse_mobile_attack_mitigations(original_text),
        }

    if "attack_tactics" in included_ioc_types:
        iocs["attack_tactics"] = {  # type: ignore
            "pre_attack": parse_pre_attack_tactics(original_text),
            "enterprise": parse_enterprise_attack_tactics(original_text),
            "mobile": parse_mobile_attack_tactics(original_text),
        }

    if "attack_techniques" in included_ioc_types:
        iocs["attack_techniques"] = {  # type: ignore
            "pre_attack": parse_pre_attack_techniques(original_text),
            "enterprise": parse_enterprise_attack_techniques(original_text),
            "mobile": parse_mobile_attack_techniques(original_text),
        }

    if "file_paths" in included_ioc_types:
        # if there are still url paths in the text, remove them so they don't get parsed as file names
        if parse_from_url_path:
            urls = _get_items(
                iocs,
                "urls",
                parse_urls,
                text,
                parse_urls_without_scheme=parse_urls_without_scheme,
                parse_unicode_iocs=parse_unicode_iocs,
            )
            text = _remove_url_paths(urls, text, parse_unicode_iocs=parse_unicode_iocs)

        iocs["file_paths"] = parse_file_paths(text)

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("find_iocs result counts: %s", {k: _count_iocs(v) for k, v in iocs.items()})
    logger.info("find_iocs completed (ioc_types_parsed=%d)", len(iocs))
    return iocs


def _count_iocs(value) -> int:
    """Sum lengths of an IOC entry — list directly, or nested dict-of-lists for attack_* groups."""
    if isinstance(value, dict):
        return sum(len(v) for v in value.values())
    return len(value)
