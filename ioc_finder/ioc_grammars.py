import copy
import re

from pyparsing import (
    CaselessLiteral,
    Char,
    Combine,
    Empty,
    FollowedBy,
    Literal,
    MatchFirst,
    NotAny,
    OneOrMore,
    Optional,
    Or,
    Regex,
    Word,
    WordEnd,
    WordStart,
    ZeroOrMore,
    alphanums,
    alphas,
    hexnums,
    nums,
    one_of,
    printables,
    pyparsing_common,
    replace_with,
)

from ioc_finder.data import (
    enterprise_attack_mitigations,
    enterprise_attack_tactics,
    enterprise_attack_techniques,
    mobile_attack_mitigations,
    mobile_attack_tactics,
    mobile_attack_techniques,
    pre_attack_tactics,
    pre_attack_techniques,
    schemes,
    tlds,
)

alphanum_word_start = WordStart(wordChars=alphanums)
alphanum_word_end = WordEnd(wordChars=alphanums)

# the label definition ignores the fact that labels should not end in an hyphen
label = Word(initChars=alphanums + "_", bodyChars=alphanums + "-_", max=63)
domain_tld = one_of(tlds, caseless=True)
domain_name = (
    alphanum_word_start
    + Combine(
        Combine(OneOrMore(label + ("." + FollowedBy(Word(alphanums + "-_")))))("domain_labels") + domain_tld("tld")
    )
    + alphanum_word_end
).set_parse_action(pyparsing_common.downcase_tokens)

ipv4_section = (
    Word(nums, asKeyword=True, max=3)
    .set_parse_action(lambda x: str(int(x[0])))
    .addCondition(lambda tokens: int(tokens[0]) < 256)
)
# basically, the grammar below says: start any words that start with a '.' or a number;
# I want to match words that start with a '.' because this will fail later in the grammar...
# and I do not want to match anything that start with a '.'
ipv4_address = (
    alphanum_word_start
    + WordStart("." + nums)
    + Combine((ipv4_section + ".") * 3 + ipv4_section)
    + NotAny(Regex(r"\.\S"))
    + alphanum_word_end
)

ipv6_word_start = WordStart(wordChars=alphanums + ":")
ipv6_word_end = WordEnd(wordChars=alphanums + ":")

hexadectet = Word(hexnums, min=1, max=4)
ipv6_address_full = ipv6_word_start + Combine((hexadectet + ":") * 7 + hexadectet)

# the condition on the end of this grammar is designed to make sure that any shortened ipv6 addresses have '::' in them
ipv6_address_shortened = Combine(OneOrMore(Or([hexadectet + Word(":"), Word(":")])) + hexadectet).addCondition(
    lambda tokens: tokens[0].count("::") > 0
)

ipv6_address = (
    Or([ipv6_address_full, ipv6_address_shortened]).addCondition(lambda tokens: tokens[0].count(":") > 1)
    + ipv6_word_end
)

complete_email_comment = Regex(r"\([a-zA-Z0-9]+\)")
# the complete_email_local_part grammar ignores the fact that characters like <<<(),:;<>@[\] >>>
# are possible in a quoted complete_email_local_part
# (and the double-quotes and backslash should be preceded by a backslash)
complete_email_local_part = Combine(
    Optional(complete_email_comment)("email_address_start_comment")
    + OneOrMore(MatchFirst([Word(alphanums + "!#$%&'*+-/=?^_`{|}~." + '"'), CaselessLiteral("\\@")]))
    + Optional(complete_email_comment)("email_address_end_comment")
)
complete_email_address = Combine(
    complete_email_local_part("email_address_local_part")
    + "@"
    + Or([domain_name, "[" + ipv4_address + "]", "[IPv6:" + ipv6_address + "]"])("email_address_domain")
)

email_local_part = Word(alphanums, bodyChars=alphanums + "+-_.").set_parse_action(pyparsing_common.downcase_tokens)
email_address = alphanum_word_start + Combine(
    email_local_part("email_address_local_part")
    + "@"
    + Or([domain_name, "[" + ipv4_address + "]", "[IPv6:" + ipv6_address + "]"])("email_address_domain")
)

url_scheme = one_of(schemes, caseless=True)
port = Word(":", nums, min=2)
url_authority = Combine(Or([email_address, domain_name, ipv4_address, ipv6_address]) + Optional(port)("port"))
# The url_path_word characters are taken from https://www.ietf.org/rfc/rfc3986.txt...
# (of particular interest is "Appendix A.  Collected ABNF for URI")
# Although the ":" character is not valid in url paths,
# some urls are written with the ":" unencoded so we include it below
url_path_word = Word(alphanums + "-._~!$&'()*+,;=:%")
url_path = Combine(OneOrMore(MatchFirst([url_path_word, Literal("/")])))
url_query = Word(printables, excludeChars="#\"']")
url_fragment = Word(printables, excludeChars="?\"']")
url = alphanum_word_start + Combine(
    url_scheme("url_scheme")
    + "://"
    + url_authority("url_authority")
    + Optional(Combine("/" + Optional(url_path)))("url_path")
    + (Optional(Combine("?" + url_query)("url_query")) & Optional(Combine("#" + url_fragment)("url_fragment")))
)
scheme_less_url = alphanum_word_start + Or(
    [
        url,
        Combine(
            Combine(url_authority("url_authority") + Combine("/" + Optional(url_path))("url_path"))
            + (Optional(Combine("?" + url_query)("url_query")) & Optional(Combine("#" + url_fragment)("url_fragment")))
        ),
    ]
)

# this allows for matching file hashes preceeded with an 'x' or 'X'...
# see https://github.com/fhightower/ioc-finder/issues/41
file_hash_word_start = WordStart(wordChars=alphanums.replace("x", "").replace("X", ""))
md5 = (
    file_hash_word_start
    + Word(hexnums, exact=32).set_parse_action(pyparsing_common.downcase_tokens)
    + alphanum_word_end
)
imphash = Combine(
    Or([CaselessLiteral("imphash"), CaselessLiteral("import hash")])
    + Optional(Word(printables, excludeChars=alphanums))
    + md5("hash"),
    joinString=" ",
    adjacent=False,
)
sha1 = (
    file_hash_word_start
    + Word(hexnums, exact=40).set_parse_action(pyparsing_common.downcase_tokens)
    + alphanum_word_end
)
sha256 = (
    file_hash_word_start
    + Word(hexnums, exact=64).set_parse_action(pyparsing_common.downcase_tokens)
    + alphanum_word_end
)
authentihash = Combine(
    CaselessLiteral("authentihash") + Optional(Word(printables, excludeChars=alphanums)) + sha256("hash"),
    joinString=" ",
    adjacent=False,
)
sha512 = (
    file_hash_word_start
    + Word(hexnums, exact=128).set_parse_action(pyparsing_common.downcase_tokens)
    + alphanum_word_end
)

year = Word("12") + Word(nums, exact=3)
cve = (
    alphanum_word_start
    + Combine(
        CaselessLiteral("cve").set_parse_action(replace_with("CVE"))
        + Word("- ").set_parse_action(replace_with("-"))
        + year("year")
        + Word("-")
        + Word(nums, min=4)("cve_id")
    )
    + alphanum_word_end
)

asn = (
    alphanum_word_start
    + Combine(
        Or(
            [
                Literal("AS") + Optional(Word("N ")).set_parse_action(replace_with("N")),
                Literal("as").set_parse_action(replace_with("ASN")),
                (Literal("asn") + Optional(" ")).set_parse_action(replace_with("ASN")),
            ]
        )
        + Word(nums)("as_number")
    )
    + alphanum_word_end
)

ipv4_cidr = (
    alphanum_word_start
    + Combine(ipv4_address("cidr_address") + "/" + Word(nums, max=2)("cidr_bit_range"))
    + alphanum_word_end
)

root_key_list = [
    "HKEY_LOCAL_MACHINE",
    "HKLM",
    "HKEY_CURRENT_CONFIG",
    "HKCC",
    "HKEY_CLASSES_ROOT",
    "HKCR",
    "HKEY_CURRENT_USER",
    "HKCU",
    "HKEY_USERS",
    "HKU",
    "HKEY_PERFORMANCE_DATA",
    "HKEY_DYN_DATA",
]
root_key = one_of(root_key_list)


def hasMultipleConsecutiveSpaces(string):
    """Return True if the given string has multiple, consecutive spaces."""
    return re.match("  +", string)


def hasBothOrNeitherAngleBrackets(string):
    """Make sure a string either has both '<' and '>' or neither of those angle brackets."""
    left_angle_bracket_in_string = "<" in string
    right_angle_bracket_in_string = ">" in string

    # if the string has both brackets...
    if left_angle_bracket_in_string and right_angle_bracket_in_string:
        return True
    # if the string has only one bracket...
    elif left_angle_bracket_in_string or right_angle_bracket_in_string:
        return False
    # if the string has neither of the brackets...
    else:
        return True


registry_key_subpath_section = Combine(
    Word("\\")
    + Optional(Word("<"))
    + Word(alphanums)
    + ZeroOrMore(
        # registry key paths may contain a file extension which requires that we capture registry
        # key path sections with a period (e.g. `notepad.exe`)
        Optional(Word(".", max=1))
        # the registry key path section can contain any alphanum text (including spaces) as long as the text is not
        # one of the registry key path root keys and as long as there are not multiple, consecutive spaces
        + Word(alphanums + " ").addCondition(
            lambda tokens: tokens[0].strip() not in root_key_list and not hasMultipleConsecutiveSpaces(tokens[0])
        )
    )
    + Optional(Word(">"))
).addCondition(lambda tokens: hasBothOrNeitherAngleBrackets(tokens[0]))
registry_key_subpath = OneOrMore(registry_key_subpath_section)
registry_key_path = (
    alphanum_word_start
    + Combine(
        Optional("<").set_parse_action(replace_with(""))
        + root_key("registry_key_root")
        + Optional(">").set_parse_action(replace_with(""))
        + registry_key_subpath("registry_key_subpath")
    )
    + alphanum_word_end
)

# see https://support.google.com/adsense/answer/2923881?hl=en
google_adsense_publisher_id = (
    alphanum_word_start
    # we use `Or([Literal("pub-")...` instead of something like `CaselessLiteral("pub-")` b/c...
    # we only want to parse "pub" when it is all upper or lowercased (not "pUb" or other, similar variations)
    + Combine(one_of("pub- PUB-") + Word(nums, exact=16)).set_parse_action(pyparsing_common.downcase_tokens)
    + alphanum_word_end
)

# see https://support.google.com/analytics/answer/7372977?hl=en
google_analytics_tracker_id = (
    alphanum_word_start
    + Combine(
        # we use `Or([Literal("ua-")...` instead of something like `CaselessLiteral("ua-")` b/c...
        # we only want to parse "ua" when it is all upper or lowercased (not "uA" or other, similar variations)
        one_of("ua- UA-")
        + Word(nums, min=6)("account_number")
        + "-"
        + Word(nums)("property_number")
    ).set_parse_action(pyparsing_common.upcase_tokens)
    + alphanum_word_end
)

# see https://en.bitcoin.it/wiki/Address
# (and https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#segwit-address-format for Bech32 addresses)
bitcoin_address = (
    alphanum_word_start
    + MatchFirst(
        [
            Regex(r"1[a-zA-Z0-9]{25,34}"),
            Regex(r"3[a-zA-Z0-9]{25,34}"),
            Regex(r"bc1[a-zA-Z0-9]{11,71}"),
        ]
    )
    + alphanum_word_end
)

monero_address = alphanum_word_start + Regex("4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}") + alphanum_word_end

# see https://github.com/fhightower/ioc-finder/issues/18
xmpp_address = alphanum_word_start + Combine(
    email_local_part("email_address_local_part") + "@" + domain_name("jabber_address_domain")
).addCondition(lambda tokens: "jabber" in tokens[0].split("@")[-1] or "xmpp" in tokens[0].split("@")[-1])

# the mac address grammar was developed from https://en.wikipedia.org/wiki/MAC_address#Notational_conventions
# handles xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx
mac_address_16_bit_section = Combine((Word(hexnums, exact=2) + one_of("- :")) * 5 + Word(hexnums, exact=2))
# handles xxxx.xxxx.xxxx
mac_address_32_bit_section = Combine((Word(hexnums, exact=4) + ".") * 2 + Word(hexnums, exact=4))
mac_address_word_start = WordStart(wordChars=alphanums + ":-.")
mac_address_word_end = WordEnd(wordChars=alphanums + ":-.")
mac_address = (
    mac_address_word_start + MatchFirst([mac_address_16_bit_section, mac_address_32_bit_section]) + mac_address_word_end
)

# the structure of an ssdeep hash is: chunksize:chunk:double_chunk
# we add a condition to the ssdeep grammar to make sure that the second section of the grammar
# (the chunk) is at least as big if not bigger than the third section (the double_chunk)
ssdeep = alphanum_word_start + Combine(
    Word(nums) + ":" + Word(alphanums + "/+", min=3) + ":" + Word(alphanums + "/+", min=3)
).addCondition(lambda tokens: len(tokens[0].split(":")[1]) >= len(tokens[0].split(":")[2]))

user_agent_platform_version = Regex(r"[0-9]+(\.[0-9]*)*")
user_agent_start = Combine(Regex(r"[Mm]ozilla/") + user_agent_platform_version)
user_agent_details = Regex(r"\(.+?\)")
user_agent_platform = Combine(
    alphanum_word_start
    + Regex(r"[a-zA-Z]{2,}/?").addCondition(lambda tokens: tokens[0].lower().strip("/") != "mozilla")
    + Optional(user_agent_platform_version)
)
user_agent = Combine(
    user_agent_start + user_agent_details + ZeroOrMore(user_agent_platform + Optional(user_agent_details)),
    joinString=" ",
    adjacent=False,
)

# https://github.com/fhightower/ioc-finder/issues/13
file_ending = Word(alphas, max=5)
windows_file_path = alphanum_word_start + Combine(
    Char(alphanums) + ":" + Word(printables + " ", exclude_chars=".") + "." + file_ending
)

# we need to add '/' and '~' to the alphanum_word_start so that the grammar will match words starting with '/' and '~'
# we add ':' to the alphanum_word_start because we want to avoid parsing urls are file paths
# (e.g. "//twitter.com" from "https://twitter.com/")
unix_file_path_wordstart = copy.deepcopy(alphanum_word_start)
unix_file_path_wordstart.wordChars.add(":")
unix_file_path_wordstart.wordChars.add("/")
unix_file_path_wordstart.wordChars.add("~")

unix_file_path = unix_file_path_wordstart + Combine(
    one_of("~ /") + Word(printables + " ", exclude_chars=".") + "." + file_ending
).addCondition(lambda tokens: "//" not in tokens[0])
file_path = Or([windows_file_path, unix_file_path]) + alphanum_word_end

# be aware that the phone_number grammar assumes that the text being sent to it has been reversed
phone_number_connector = Word(" .-", max=3)
phone_number_format_1 = Combine(
    Word(nums, exact=4)
    + phone_number_connector
    + Word(nums, exact=3)
    + Optional(phone_number_connector + Optional(")") + Word(nums) + Optional("("))
)

phone_number = Or([phone_number_format_1])

attack_sub_technique = Literal(".") + Word(nums, exact=3)
pre_attack_tactics_grammar = (
    alphanum_word_start
    + Or([CaselessLiteral(i) for i in pre_attack_tactics]).set_parse_action(pyparsing_common.upcase_tokens)
    + alphanum_word_end
)
pre_attack_techniques_grammar = (
    alphanum_word_start
    + Combine(
        one_of(pre_attack_techniques, caseless=True).set_parse_action(pyparsing_common.upcase_tokens)
        + Optional(attack_sub_technique)
    )
    + alphanum_word_end
)

enterprise_attack_mitigations_grammar = (
    alphanum_word_start + one_of(enterprise_attack_mitigations, caseless=True) + alphanum_word_end
)
enterprise_attack_tactics_grammar = (
    alphanum_word_start
    + one_of(enterprise_attack_tactics, caseless=True).set_parse_action(pyparsing_common.upcase_tokens)
    + alphanum_word_end
)
enterprise_attack_techniques_grammar = (
    alphanum_word_start
    + Combine(
        one_of(enterprise_attack_techniques, caseless=True).set_parse_action(pyparsing_common.upcase_tokens)
        + Optional(attack_sub_technique)
    )
    + alphanum_word_end
)

mobile_attack_mitigations_grammar = (
    alphanum_word_start + one_of(mobile_attack_mitigations, caseless=True) + alphanum_word_end
)
mobile_attack_tactics_grammar = (
    alphanum_word_start
    + one_of(mobile_attack_tactics, caseless=True).set_parse_action(pyparsing_common.upcase_tokens)
    + alphanum_word_end
)
mobile_attack_techniques_grammar = (
    alphanum_word_start
    + Combine(
        one_of(mobile_attack_techniques, caseless=True).set_parse_action(pyparsing_common.upcase_tokens)
        + Optional(attack_sub_technique)
    )
    + alphanum_word_end
)

tlp_colors = one_of("red amber green white", caseless=True)

tlp_label = Combine(
    CaselessLiteral("tlp")
    + Or([Literal(":"), Literal("-"), Literal(" "), Empty()]).set_parse_action(lambda x: ":")
    + tlp_colors
).set_parse_action(pyparsing_common.upcase_tokens)
