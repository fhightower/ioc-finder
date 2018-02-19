#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Simple python package for finding indicators of compromise in text."""

from collections import OrderedDict
try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser
import os
import re


def _get_regexes():
    """Read the regexes."""
    REGEX_FILE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "./data/regexes.ini"))

    config = ConfigParser.ConfigParser()
    with open(REGEX_FILE_PATH) as f:
        config.readfp(f)

    # initialize the indicator order
    indicator_regexes = OrderedDict()

    for indicator_type in config.sections():
        if indicator_type == 'email':
            indicator_regexes[indicator_type] = {
                'regex': config.get(indicator_type, 'regex') + config.get('domain', 'regex')
            }
        else:
            indicator_regexes[indicator_type] = {
                'regex': config.get(indicator_type, 'regex'),
            }

        try:
            remove = config.get(indicator_type, 'remove')
        except ConfigParser.NoOptionError:
            pass
        else:
            indicator_regexes[indicator_type]['remove'] = remove

    return indicator_regexes


def find_iocs(text):
    """Find indicators of compromise in the given text."""
    iocs = dict()
    indicator_regexes = _get_regexes()

    for indicator_type, indicator_regex in indicator_regexes.items():
        iocs[indicator_type] = set()

        for match in re.finditer(indicator_regex['regex'], text):
            if indicator_type == "ipv4":
                ip = match.string[match.start():match.end()]
                # strip leading 0s
                ip = '.'.join([str(int(x)) for x in ip.split('.')])
                iocs[indicator_type].add(ip)
            elif indicator_type == "domain":
                iocs[indicator_type].add(match.string[match.start():match.end()])
            # handle email addresses
            elif indicator_type == "email":
                iocs[indicator_type].add(match.string[match.start():match.end()])
            elif indicator_type == "url":
                iocs[indicator_type].add(match.string[match.start():match.end()])
            elif indicator_type in ['md5', 'sha1', 'sha256']:
                iocs[indicator_type].add(match.string[match.start():match.end()])
            else:
                print("Unknown indicator type: {}".format(indicator_type))

            # if appropriate, remove the indicator from the text
            if indicator_regex.get('remove'):
                text = text.replace(match.string[match.start():match.end()], "")

    return iocs
