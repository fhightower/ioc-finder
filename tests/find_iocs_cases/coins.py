from pytest import param

COIN_DATA = [
    param(
        """1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.
        P2SH type starting with the number 3, eg: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy.
        Bech32 type starting with bc1, eg: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq""",
        {
            "bitcoin_addresses": [
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
                "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            ]
        },
        {},
        id="bitcoin_address_1",
    ),
    param(
        """1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.
        P2SH type starting with the number 3, eg: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy.
        Bech32 type starting with bc1, eg: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq""",
        {
            "bitcoin_addresses": [
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
                "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            ]
        },
        {},
        id="bitcoin_address_1",
    ),
    param(
        """1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.
        P2SH type starting with the number 3, eg: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy.
        Bech32 type starting with bc1, eg: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq""",
        {
            "bitcoin_addresses": [
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
                "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            ]
        },
        {},
        id="bitcoin_address_1",
    ),
    param(
        """1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.
        P2SH type starting with the number 3, eg: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy.
        Bech32 type starting with bc1, eg: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq""",
        {
            "bitcoin_addresses": [
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
                "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            ]
        },
        {},
        id="bitcoin_address_1",
    ),
    param(
        "496aKKdqF1xQSSEzw7wNrkZkDUsCD5cSmNCfVhVgEps52WERBcLDGzdF5UugmFoHMm9xRJdewvK2TFfAJNwEV25rTcVF5Vp",
        {
            "monero_addresses": [
                "496aKKdqF1xQSSEzw7wNrkZkDUsCD5cSmNCfVhVgEps52WERBcLDGzdF5UugmFoHMm9xRJdewvK2TFfAJNwEV25rTcVF5Vp"
            ]
        },
        {},
        id="monero_1",
    ),
    param(
        "49Bmp3SfddJRRGNW7GhHyAA2JgcYmZ4EGEix6p3eMNFCd15P2VsK9BHWcZWUNYF3nhf17MoRTRK4j5b7FUMA9zanSn9D3Nk 498s2XeKWYSEhQHGxdMULWdrpaKvSkDsq4855mCuksNL6ez2dk4mMQm8epbr9xvn5LgLPzD5uL9EGeRqWUdEZha1HmZqcyh",
        {
            "monero_addresses": [
                "49Bmp3SfddJRRGNW7GhHyAA2JgcYmZ4EGEix6p3eMNFCd15P2VsK9BHWcZWUNYF3nhf17MoRTRK4j5b7FUMA9zanSn9D3Nk",
                "498s2XeKWYSEhQHGxdMULWdrpaKvSkDsq4855mCuksNL6ez2dk4mMQm8epbr9xvn5LgLPzD5uL9EGeRqWUdEZha1HmZqcyh",
            ]
        },
        {},
        id="monero_2",
    ),
]
