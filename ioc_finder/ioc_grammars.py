#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import copy

from pyparsing import alphanums, alphas, printables, nums, hexnums
from pyparsing import (
    OneOrMore,
    Word,
    Combine,
    Optional,
    Or,
    Regex,
    WordStart,
    WordEnd,
    replaceWith,
    downcaseTokens,
    NotAny,
)

from data_lists import tlds, schemes

alphanum_word_start = WordStart(wordChars=alphanums)
alphanum_word_end = WordEnd(wordChars=alphanums)

# the label definition ignores the fact that labels should not end in an hyphen
label = Word(initChars=alphanums, bodyChars=alphanums + '-', max=63)
domain_tld = Or(tlds)
domain_name = (
    alphanum_word_start
    + Combine(Combine(OneOrMore(label + ('.')))('domain_labels') + domain_tld('tld'))
    + alphanum_word_end
)

ipv4_section = Word(nums, asKeyword=True).addCondition(lambda tokens: int(tokens[0]) < 256)
# basically, the grammar below says: start any words that start with a '.' or a number; I want to match words that start with a '.' because this will fail later in the grammar and I do not want to match anything that start with a '.'
ipv4_address = (
    alphanum_word_start
    + WordStart('.' + nums)
    + Combine((ipv4_section + '.') * 3 + ipv4_section)
    + NotAny(Regex('\.\S'))
    + alphanum_word_end
)

hexadectet = Word(hexnums, min=1, max=4)
ipv6_address_full = alphanum_word_start + Combine((hexadectet + ":") * 7 + hexadectet)
# todo: the ipv6_address_shortened grammar needs some fine-tuning so it doesn't pull in content too broadly
ipv6_address_shortened = Combine(OneOrMore(Or([hexadectet + Word(':'), Word(':')])) + hexadectet)
ipv6_address = Or([ipv6_address_full, ipv6_address_shortened]) + alphanum_word_end

complete_email_comment = Combine('(' + Word(printables.replace(')', '')) + ')')
# the complete_email_local_part grammar ignores the fact that characters like <<<(),:;<>@[\] >>> are possible in a quoted complete_email_local_part (and the double-quotes and backslash should be preceded by a backslash)
complete_email_local_part = Combine(
    Optional(complete_email_comment)('email_address_comment')
    + Word(alphanums + "!#$%&'*+-/=?^_`{|}~." + '"')
    + Optional(complete_email_comment)('email_address_comment')
)
complete_email_address = Combine(
    complete_email_local_part('email_address_local_part')
    + "@"
    + Or([domain_name, '[' + ipv4_address + ']', '[IPv6:' + ipv6_address + ']'])('email_address_domain')
)

email_local_part = Word(alphanums + "+-_.")
email_address = alphanum_word_start + Combine(
    email_local_part('email_address_local_part')
    + "@"
    + Or([domain_name, '[' + ipv4_address + ']', '[IPv6:' + ipv6_address + ']'])('email_address_domain')
)

url_scheme = Or(schemes)
# todo: move the handling for port to the domain grammar - maybe?
port = Combine(':' + Word(nums))
url_authority = Combine(Or([complete_email_address, domain_name, ipv4_address, ipv6_address]) + Optional(port)('port'))
url_path = Combine(OneOrMore(Word(alphanums + "$-_.+!*'(),") + Optional('/')))
url_query = Word(printables, excludeChars='#"\']')
url_fragment = Word(printables, excludeChars='?"\']')
url = alphanum_word_start + Combine(
    url_scheme('url_scheme')
    + '://'
    + url_authority('url_authority')
    + Optional(Combine('/' + Optional(url_path)))('url_path')
    + (Optional(Combine('?' + url_query)('url_query')) & Optional(Combine('#' + url_fragment)('url_fragment')))
)
scheme_less_url = alphanum_word_start + Combine(
    Or(
        [
            Combine(
                url_scheme('url_scheme')
                + '://'
                + url_authority('url_authority')
                + Optional(Combine('/' + Optional(url_path)))('url_path')
            ),
            Combine(url_authority('url_authority') + Combine('/' + Optional(url_path))('url_path')),
        ]
    )
    + (Optional(Combine('?' + url_query)('url_query')) & Optional(Combine('#' + url_fragment)('url_fragment')))
)

md5 = alphanum_word_start + Word(hexnums, exact=32).setParseAction(downcaseTokens) + alphanum_word_end
sha1 = alphanum_word_start + Word(hexnums, exact=40).setParseAction(downcaseTokens) + alphanum_word_end
sha256 = alphanum_word_start + Word(hexnums, exact=64).setParseAction(downcaseTokens) + alphanum_word_end
sha512 = alphanum_word_start + Word(hexnums, exact=128).setParseAction(downcaseTokens) + alphanum_word_end

year = Word('12') + Word(nums, exact=3)
cve = (
    alphanum_word_start
    + Combine(
        Or(['cve', 'CVE']).setParseAction(replaceWith('CVE'))
        + Word('- ').setParseAction(replaceWith('-'))
        + year('year')
        + Word('-')
        + Word(nums, min=4)('cve_id')
    )
    + alphanum_word_end
)

asn = (
    alphanum_word_start
    + Combine(
        Or(['as', 'AS']).setParseAction(replaceWith('AS'))
        + Optional(Word('nN ')).setParseAction(replaceWith('N'))
        + Word(nums)('as_number')
    )
    + alphanum_word_end
)

# todo: implement ipv6 cidr ranges
ipv4_cidr = (
    alphanum_word_start
    + Combine(ipv4_address('cidr_address') + '/' + Word(nums, max=2)('cidr_bit_range'))
    + alphanum_word_end
)

root_key = Or(
    [
        'HKEY_LOCAL_MACHINE',
        'HKLM',
        'HKEY_CURRENT_CONFIG',
        'HKCC',
        'HKEY_CLASSES_ROOT',
        'HKCR',
        'HKEY_CURRENT_USER',
        'HKCU',
        'HKEY_USERS',
        'HKU',
        'HKEY_PERFORMANCE_DATA',
        'HKEY_DYN_DATA',
    ]
)
registry_key_subpath = OneOrMore(Word('\\') + Word(alphas))
registry_key_path = (
    alphanum_word_start
    + Combine(root_key('registry_key_root') + registry_key_subpath('registry_key_subpath'))
    + alphanum_word_end
)

# see https://support.google.com/adsense/answer/2923881?hl=en
google_adsense_publisher_id = alphanum_word_start + Combine('pub-' + Word(nums, exact=16)) + alphanum_word_end

# see https://support.google.com/analytics/answer/7372977?hl=en
google_analytics_tracker_id = (
    alphanum_word_start
    + Combine('UA-' + Word(nums, min=6)('account_number') + '-' + Word(nums)('property_number'))
    + alphanum_word_end
)

# see https://en.bitcoin.it/wiki/Address (and https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#segwit-address-format for more info on Bech32 addresses)
bitcoin_address = (
    alphanum_word_start
    + Or(
        [
            Combine('1' + Word(alphanums, min=25, max=34)),
            Combine('3' + Word(alphanums, min=25, max=34)),
            Combine('bc1' + Word(alphanums, min=11, max=71)),
        ]
    )
    + alphanum_word_end
)

# see https://github.com/fhightower/ioc-finder/issues/18
xmpp_domain_name = copy.deepcopy(domain_name).addCondition(lambda tokens: 'jabber' in tokens[0] or 'xmpp' in tokens[0])
xmpp_address = alphanum_word_start + Combine(
    email_local_part('email_address_local_part') + "@" + xmpp_domain_name('jabber_address_domain')
)

mac_address_section = Or([Word(hexnums, exact=2), Word(hexnums, exact=4)])
# handles xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx
mac_address_16_bit_section = Combine((mac_address_section + Or(['-', ':'])) * 5 + mac_address_section)
# handles xxxx.xxxx.xxxx
mac_address_32_bit_section = Combine((mac_address_section + '.') * 2 + mac_address_section)
mac_address = alphanum_word_start + Or([mac_address_16_bit_section, mac_address_32_bit_section]) + alphanum_word_end

ssdeep = alphanum_word_start + Combine(Word(nums) + ':' + Word(alphanums + '+/:'))
