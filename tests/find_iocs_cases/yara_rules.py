from pytest import param

SIMPLE_YARA_RULE = 'rule TestRule { strings: $a = "evil" condition: $a }'

YARA_DATA = [
    param(
        SIMPLE_YARA_RULE,
        {"yara_rules": [SIMPLE_YARA_RULE]},
        {"included_ioc_types": ["yara_rules"]},
        id="yara_simple",
    ),
    param(
        # private/global modifiers + tags + meta + strings + condition
        "private global rule FullExample : malware trojan {\n"
        "    meta:\n"
        '        author = "ioc-finder"\n'
        '        description = "exercise every section"\n'
        "    strings:\n"
        '        $a = "evil"\n'
        "        $b = { 4D 5A 90 ?? [4-6] (62 | 63) }\n"
        "        $c = /md5: [0-9a-f]{32}/i\n"
        "    condition:\n"
        "        any of them\n"
        "}",
        {
            "yara_rules": [
                "private global rule FullExample : malware trojan {\n"
                "    meta:\n"
                '        author = "ioc-finder"\n'
                '        description = "exercise every section"\n'
                "    strings:\n"
                '        $a = "evil"\n'
                "        $b = { 4D 5A 90 ?? [4-6] (62 | 63) }\n"
                "        $c = /md5: [0-9a-f]{32}/i\n"
                "    condition:\n"
                "        any of them\n"
                "}"
            ]
        },
        {"included_ioc_types": ["yara_rules"]},
        id="yara_full_with_modifiers_tags_hex_regex",
    ),
    param(
        # Two rules back-to-back must both be returned, with `import` lines
        # in between left out of the matches.
        'rule One { condition: true }\n\nimport "pe"\n\nrule Two { strings: $s = "x" condition: $s }',
        {
            "yara_rules": [
                "rule One { condition: true }",
                'rule Two { strings: $s = "x" condition: $s }',
            ]
        },
        {"included_ioc_types": ["yara_rules"]},
        id="yara_multiple_rules_with_import_between",
    ),
    param(
        # A `}` inside a quoted string must not close the rule body.
        'rule QuoteEscape { strings: $a = "close }" condition: $a }',
        {"yara_rules": ['rule QuoteEscape { strings: $a = "close }" condition: $a }']},
        {"included_ioc_types": ["yara_rules"]},
        id="yara_brace_in_quoted_string",
    ),
    param(
        # `}` inside a /regex/ literal must not close the rule body either.
        "rule RegexEscape { strings: $a = /a}b/ condition: $a }",
        {"yara_rules": ["rule RegexEscape { strings: $a = /a}b/ condition: $a }"]},
        {"included_ioc_types": ["yara_rules"]},
        id="yara_brace_in_regex",
    ),
    param(
        # Block and line comments may contain stray braces — both must be
        # stepped over by the body walker.
        "rule Commented {\n"
        "    /* a } stray brace in a block comment */\n"
        "    // and a } in a line comment\n"
        "    condition: true\n"
        "}",
        {
            "yara_rules": [
                "rule Commented {\n"
                "    /* a } stray brace in a block comment */\n"
                "    // and a } in a line comment\n"
                "    condition: true\n"
                "}"
            ]
        },
        {"included_ioc_types": ["yara_rules"]},
        id="yara_brace_in_comments",
    ),
    param(
        # No `condition:` keyword: not a real rule, must be rejected.
        'rule Stub { strings: $a = "x" }',
        {"yara_rules": []},
        {"included_ioc_types": ["yara_rules"]},
        id="yara_no_condition_rejected",
    ),
    param(
        # Word "rule" in prose followed by a code-fence-shaped block must
        # not match because the block has no `condition:`.
        "Each rule X { does what you would expect } in this DSL.",
        {"yara_rules": []},
        {"included_ioc_types": ["yara_rules"]},
        id="yara_prose_rejected",
    ),
    param(
        # Embedded inside a paragraph of report text.
        "We deployed the following rule to all sensors:\n\n"
        "rule Deployed { condition: true }\n\n"
        "and observed three hits in the first hour.",
        {"yara_rules": ["rule Deployed { condition: true }"]},
        {"included_ioc_types": ["yara_rules"]},
        id="yara_embedded_in_prose",
    ),
]
