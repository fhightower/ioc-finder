from pytest import param

UA_DATA = [
    param(
        "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; InfoPath.1)",
        {"user_agents": ["Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; InfoPath.1)"]},
        {},
        id="user_agent_1",
    ),
    param(
        "mozilla/5.0 (windows nt 6.1; wow64) applewebkit/535.11 (khtml, like gecko) chrome/17.0.963.56 safari/535.11 mozilla/5.0 (windows nt 6.1; wow64; rv:11.0) gecko firefox/11.0",
        {
            "user_agents": [
                "mozilla/5.0 (windows nt 6.1; wow64) applewebkit/535.11 (khtml, like gecko) chrome/17.0.963.56 safari/535.11",
                "mozilla/5.0 (windows nt 6.1; wow64; rv:11.0) gecko firefox/11.0",
            ]
        },
        {},
        id="user_agent_2",
    ),
    param(
        "Mozilla/5.0 (Windows nt 6.1; wow64) Applewebkit/535.11 (khtml, like Gecko) Chrome/17.0.963.56 Safari/535.11 Mozilla/5.0 (Windows nt 6.1; wow64; rv:11.0) Gecko Firefox/11.0",
        {
            "user_agents": [
                "Mozilla/5.0 (Windows nt 6.1; wow64) Applewebkit/535.11 (khtml, like Gecko) Chrome/17.0.963.56 Safari/535.11",
                "Mozilla/5.0 (Windows nt 6.1; wow64; rv:11.0) Gecko Firefox/11.0",
            ]
        },
        {},
        id="user_agent_3",
    ),
]
