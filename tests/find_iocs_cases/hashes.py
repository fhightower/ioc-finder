from pytest import param

HASH_DATA = [
    param(
        "{} {} {} {} {}".format("A" * 32, "a" * 32, "b" * 40, "c" * 64, "d" * 128),
        {
            "md5s": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "sha1s": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
            "sha256s": ["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],
            "sha512s": [
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            ],
        },
        {},
        id="random_hash_1",
    ),
    param(
        "1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U",
        {"ssdeeps": ["1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U"]},
        {},
        id="ssdeep_1",
    ),
    param(
        "ahdfadsfa 1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U,000/000/000000001 adfasf",
        {"ssdeeps": ["1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U"]},
        {},
        id="ssdeep_2",
    ),
    param(
        """c2b257868686c861d43c6cf3de146b8812778c8283f7d
        Threat  Zepakab/Zebrocy Downloader
        ssdeep  12288:QYV6MorX7qzuC3QHO9FQVHPF51jgcSj2EtPo/V7I6R+Lqaw8i6hG0:vBXu9HGaVHh4Po/VU6RkqaQ6F""",
        {"ssdeeps": ["12288:QYV6MorX7qzuC3QHO9FQVHPF51jgcSj2EtPo/V7I6R+Lqaw8i6hG0:vBXu9HGaVHh4Po/VU6RkqaQ6F"]},
        {},
        id="ssdeep_3",
    ),
    param(
        """393216:EW/eKCo9QgoHfHYebwoyC0QStQYEb+G8j3wfVOglnimQyCK+mteYREDWXKF2b:MKg3lbwoyCnCkNHlnimfCSQx8b,"000/000/000000001"
        196608:AGSE26mYSK0iwH8HW9TDl0vnvCZwZEkzzeap7R:Ak28siwH8eRSn25k3eg,"000/000/000000002"
        98304:O1OCzezOgr4XMP7Af0+Kh7MzplFKuu5XcS9QnCD/VWR6yf4OB6S/mwRTwjf0ih87:k/Y4XMT7YguEXqCD/VWR6yf4Ux/mwR0S,"000/000/000000003"
        96:ukILJhn54RewghSib4xGEHVLFNs+4tihJW6jJenUQrsIvpMMjUg:uk0Jx54usxJHh4gJrJenUQrs2pvIg,"000/000/000000004"
        196608:rNI4QlKQbWQobu0u3QRBBibfv+Z4Hjy5M+IjunAadLLtt42fAtQSqFhx:rNkK2obu0uBb3K4H28yAGc4RSax,"000/000/000000005"
        1536:mFbhArcCMbR0S/kjzU6El4mUIR2JPmvY3lpKa38fTXcTns+b3tfZyCLtRs:obNCMbWpU6SzFAPV3lpCjCsQRZyQt6,"000/000/000000006"
        48:CScrEd3jk5BsRSFCWfVsEWABbbpnWSgSX45dc6b5Qla9A+o5R6k7CyNRD5J:XcrEdzHRSFr9sE7XnsDe1CyNRNJ,"000/000/000000007"
        24:N8Rw5AF4REesFtPP6k216xoWya1oxOKHHwa8peRK8FdigZY5tODrRRK8RfMfde8:N8Rw5AF4+XPyooa2EKnwaGeRJFYpfwzQ,"000/000/000000008"
        1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U,"000/000/000000009""",
        {
            "ssdeeps": [
                "393216:EW/eKCo9QgoHfHYebwoyC0QStQYEb+G8j3wfVOglnimQyCK+mteYREDWXKF2b:MKg3lbwoyCnCkNHlnimfCSQx8b",
                "196608:AGSE26mYSK0iwH8HW9TDl0vnvCZwZEkzzeap7R:Ak28siwH8eRSn25k3eg",
                "98304:O1OCzezOgr4XMP7Af0+Kh7MzplFKuu5XcS9QnCD/VWR6yf4OB6S/mwRTwjf0ih87:k/Y4XMT7YguEXqCD/VWR6yf4Ux/mwR0S",
                "96:ukILJhn54RewghSib4xGEHVLFNs+4tihJW6jJenUQrsIvpMMjUg:uk0Jx54usxJHh4gJrJenUQrs2pvIg",
                "1536:mFbhArcCMbR0S/kjzU6El4mUIR2JPmvY3lpKa38fTXcTns+b3tfZyCLtRs:obNCMbWpU6SzFAPV3lpCjCsQRZyQt6",
                "48:CScrEd3jk5BsRSFCWfVsEWABbbpnWSgSX45dc6b5Qla9A+o5R6k7CyNRD5J:XcrEdzHRSFr9sE7XnsDe1CyNRNJ",
                "24:N8Rw5AF4REesFtPP6k216xoWya1oxOKHHwa8peRK8FdigZY5tODrRRK8RfMfde8:N8Rw5AF4+XPyooa2EKnwaGeRJFYpfwzQ",
                "1536:yB+A8bMtMeRlbIzvDqZL4QzNxVDm+5gt+M2hDDDvNZ3YZ7sU:N4tMsbOGcyrV6BQvnoZ4U",
                "196608:rNI4QlKQbWQobu0u3QRBBibfv+Z4Hjy5M+IjunAadLLtt42fAtQSqFhx:rNkK2obu0uBb3K4H28yAGc4RSax",
            ]
        },
        {},
        id="ssdeep_4",
    ),
    param(
        """SHA-256 093e394933c4545ba7019f511961b9a5ab91156cf791f45de074acad03d1a44a
        Dropper imphash: 18ddf28a71089acdbab5038f58044c0a
        C2 IP: 210.209.127.8:443
        imphash: 18ddf28a71089acdbab5038f58044c0a
        imphash 18ddf28a71089acdbab5038f58044c0a
        imphash  18ddf28a71089acdbab5038f58044c0a
        imphash:     18ddf28a71089acdbab5038f58044c0a
        imphash\t18ddf28a71089acdbab5038f58044c0a
        imphash\n18ddf28a71089acdbab5038f58044c0a
        imphash - 18ddf28a71089acdbab5038f58044c0a""",
        {
            "imphashes": [
                "18ddf28a71089acdbab5038f58044c0a",
                "18ddf28a71089acdbab5038f58044c0a",
                "18ddf28a71089acdbab5038f58044c0a",
            ],
            "ipv4s": ["210.209.127.8"],
            "sha256s": ["093e394933c4545ba7019f511961b9a5ab91156cf791f45de074acad03d1a44a"],
        },
        {},
        id="imphash_1",
    ),
    param(
        """SHA-256 093e394933c4545ba7019f511961b9a5ab91156cf791f45de074acad03d1a44a
        Dropper import hash: 18ddf28a71089acdbab5038f58044c0a
        C2 IP: 210.209.127.8:443
        import hash: 18ddf28a71089acdbab5038f58044c0a
        import hash 18ddf28a71089acdbab5038f58044c0a
        import hash  18ddf28a71089acdbab5038f58044c0a
        import hash:     18ddf28a71089acdbab5038f58044c0a
        import hash\t18ddf28a71089acdbab5038f58044c0a
        import hash\n18ddf28a71089acdbab5038f58044c0a
        import hash - 18ddf28a71089acdbab5038f58044c0a""",
        {
            "imphashes": [
                "18ddf28a71089acdbab5038f58044c0a",
                "18ddf28a71089acdbab5038f58044c0a",
                "18ddf28a71089acdbab5038f58044c0a",
            ],
            "ipv4s": ["210.209.127.8"],
            "sha256s": ["093e394933c4545ba7019f511961b9a5ab91156cf791f45de074acad03d1a44a"],
        },
        {},
        id="imphash_3",
    ),
    param(
        """SHA-256 093e394933c4545ba7019f511961b9a5ab91156cf791f45de074acad03d1a44a
        Dropper IMPORT HASH: 18ddf28a71089acdbab5038f58044c0a
        C2 IP: 210.209.127.8:443
        IMPORT HASH: 18ddf28a71089acdbab5038f58044c0a
        IMPORT HASH 18ddf28a71089acdbab5038f58044c0a
        IMPORT HASH  18ddf28a71089acdbab5038f58044c0a
        IMPORT HASH:     18ddf28a71089acdbab5038f58044c0a
        IMPORT HASH\t18ddf28a71089acdbab5038f58044c0a
        IMPORT HASH\n18ddf28a71089acdbab5038f58044c0a
        IMPORT HASH - 18ddf28a71089acdbab5038f58044c0a""",
        {
            "imphashes": [
                "18ddf28a71089acdbab5038f58044c0a",
                "18ddf28a71089acdbab5038f58044c0a",
                "18ddf28a71089acdbab5038f58044c0a",
            ],
            "ipv4s": ["210.209.127.8"],
            "sha256s": ["093e394933c4545ba7019f511961b9a5ab91156cf791f45de074acad03d1a44a"],
        },
        {},
        id="imphash_4",
    ),
    param(
        """
        authentihash 3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        authentihash   3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        authentihash: 3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        authentihash:     3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        authentihash - 3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        authentihash-3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        authentihash\t3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        authentihash\n3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        """,
        {
            "authentihashes": [
                "3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4",
                "3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4",
                "3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4",
            ]
        },
        {},
        id="authentihash_1",
    ),
    param(
        """
        AUTHENTIHASH 3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        AUTHENTIHASH   3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        AUTHENTIHASH: 3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        AUTHENTIHASH:     3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        AUTHENTIHASH - 3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        AUTHENTIHASH-3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        AUTHENTIHASH\t3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        AUTHENTIHASH\n3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4',
        """,
        {
            "authentihashes": [
                "3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4",
                "3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4",
                "3f1b149d07e7e8636636b8b7f7043c40ed64a10b28986181fb046c498432c2d4",
            ]
        },
        {},
        id="authentihash_2",
    ),
]
