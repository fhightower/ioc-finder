from pytest import param

HASH_DATA = [
    param(
        "{} {} {} {} {}".format('A' * 32, 'a' * 32, 'b' * 40, 'c' * 64, 'd' * 128),
        {
            "md5s": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "sha1s": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
            "sha256s": ["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],
            "sha512s": ["dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"]
        },
        id="hash_1"
    )
]
