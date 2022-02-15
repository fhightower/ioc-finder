def case_email_len_10_and_ipv4():
    text = "a@example.com test@a.com bingo@en.wikipedia.com foo@a.com'.format('a'*63 bar@b.a.com'.format('a'*63, 'a'*63 bad@test-ing.com me@2600.com john.smith(comment)@example.com (comment)john.smith@example.com \"John..Doe\"@example.com' test@[192.168.0.1]"
    results = {
        "email_addresses": [
            "a@example.com",
            "bad@test-ing.com",
            "bar@b.a.com",
            "bingo@en.wikipedia.com",
            "foo@a.com",
            "john.smith@example.com",
            "me@2600.com",
            "test@[192.168.0.1]",
            "test@a.com",
        ],
        "email_addresses_complete": [
            "a@example.com",
            "test@a.com",
            "bingo@en.wikipedia.com",
            "foo@a.com",
            "bar@b.a.com",
            "bad@test-ing.com",
            "me@2600.com",
            "john.smith(comment)@example.com",
            "(comment)john.smith@example.com",
            "\"John..Doe\"@example.com",
            "test@[192.168.0.1]",
        ],
        "ipv4s": [
            "192.168.0.1"
        ],
        "domains": [
            "a.com",
            "en.wikipedia.com",
            "b.a.com",
            "test-ing.com",
            "2600.com",
            "example.com"
        ]
    }
    return text, results
