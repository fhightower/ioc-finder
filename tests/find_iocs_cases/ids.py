from pytest import param

ID_DATA = [
    param(
        "pub-1234567891234567",
        {"google_adsense_publisher_ids": ["pub-1234567891234567"]},
        {},
        id="google_publisher_id_1",
    ),
    param(
        "<body> pub-1234567891234567 pub-9383614236930773 </body>",
        {"google_adsense_publisher_ids": ["pub-1234567891234567", "pub-9383614236930773"]},
        {},
        id="google_publisher_id_2",
    ),
    param(
        "<head> UA-000000-2 </head>", {"google_analytics_tracker_ids": ["UA-000000-2"]}, {}, id="google_analytics_id_1"
    ),
    param(
        "<head>UA-000000-2 UA-00000000-99</head>",
        {"google_analytics_tracker_ids": ["UA-000000-2", "UA-00000000-99"]},
        {},
        id="google_publisher_id_2",
    ),
]
