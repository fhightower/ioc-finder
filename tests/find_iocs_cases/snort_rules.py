from pytest import param

SIMPLE_SNORT_RULE = 'alert tcp any any -> any 80 (msg:"WEB-MISC test"; sid:1000001; rev:1;)'

SNORT_DATA = [
    param(
        SIMPLE_SNORT_RULE,
        {"snort_rules": [SIMPLE_SNORT_RULE]},
        {"included_ioc_types": ["snort_rules"]},
        id="snort_simple",
    ),
    param(
        # Two rules on consecutive lines should both be returned, in order.
        'alert tcp any any -> any 80 (msg:"first"; sid:1;)\ndrop udp $HOME_NET any -> any 53 (msg:"second"; sid:2;)',
        {
            "snort_rules": [
                'alert tcp any any -> any 80 (msg:"first"; sid:1;)',
                'drop udp $HOME_NET any -> any 53 (msg:"second"; sid:2;)',
            ]
        },
        {"included_ioc_types": ["snort_rules"]},
        id="snort_multiple",
    ),
    param(
        # Inline pcre with a parenthesised group must not throw off the
        # paren counter; the body has nested () and an embedded ;.
        'alert http any any -> any any (msg:"PCRE test"; pcre:"/foo(?:bar|baz)quux/i"; sid:42;)',
        {"snort_rules": ['alert http any any -> any any (msg:"PCRE test"; pcre:"/foo(?:bar|baz)quux/i"; sid:42;)']},
        {"included_ioc_types": ["snort_rules"]},
        id="snort_pcre_with_nested_parens",
    ),
    param(
        # Quoted strings inside the body may contain `)` — the extractor
        # must skip parens inside double-quoted runs.
        'alert tcp any any -> any any (msg:"smiley :)"; sid:7;)',
        {"snort_rules": ['alert tcp any any -> any any (msg:"smiley :)"; sid:7;)']},
        {"included_ioc_types": ["snort_rules"]},
        id="snort_paren_in_quoted_msg",
    ),
    param(
        # Rule embedded between paragraphs of prose.
        "Here is the rule the team wrote:\n"
        '   alert tcp any any -> 10.0.0.0/8 22 (msg:"SSH attempt"; sid:9001;)\n'
        "and that's what we deployed.",
        {"snort_rules": ['alert tcp any any -> 10.0.0.0/8 22 (msg:"SSH attempt"; sid:9001;)']},
        {"included_ioc_types": ["snort_rules"]},
        id="snort_embedded_in_prose",
    ),
    param(
        # Action+proto words in plain English must NOT match — the lack of
        # a `sid:` discriminator filters them out.
        "We had to drop udp traffic at any port.",
        {"snort_rules": []},
        {"included_ioc_types": ["snort_rules"]},
        id="snort_prose_no_sid",
    ),
    param(
        # An unbalanced rule (truncated, missing close paren) must be
        # rejected rather than swallowing the rest of the document.
        'alert tcp any any -> any 80 (msg:"truncated"; sid:1;\nAnd here is the next paragraph.',
        {"snort_rules": []},
        {"included_ioc_types": ["snort_rules"]},
        id="snort_unbalanced_rejected",
    ),
]
