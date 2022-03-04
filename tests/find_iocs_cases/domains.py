from pytest import param

DOMAIN_DATA = [
    param(
        "this is just a (google.com) test of example.com",
        {"domains": ["google.com", "example.com"]},
        {},
        id="domain_1"
    ),
    param(
        "https://asf.goole.com/mail?url=http%3A%2F%2Ffreasdfuewriter.com%2Fcs%2Fimage%2FCommerciaE.jpg&t=1575955624&ymreqid=733bc9eb-e8f-34cb-1cb5-120010019e00&sig=x2Pa2oOYxanG52s4vyCEFg--~Chttp://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip",
        {"domains": ["google.com", "freasdfuewriter.com", "uniddloos.zddfdd.org"],
         "urls": ["https://asf.goole.com/mail?url=http%3A%2F%2Ffreasdfuewriter.com%2Fcs%2Fimage%2FCommerciaE.jpg&t=1575955624&ymreqid=733bc9eb-e8f-34cb-1cb5-120010019e00&sig=x2Pa2oOYxanG52s4vyCEFg--~Chttp://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip",
                  "http://freasdfuewriter.com%2Fcs%2Fimage%2FCommerciaE.jpg&t=1575955624&ymreqid=733bc9eb-e8f-34cb-1cb5-120010019e00&sig=x2Pa2oOYxanG52s4vyCEFg--~Chttp://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip",
                  "http://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip"]},
        {},
        id="domain-issue_104__domains_read_from_percent_encoded_url_query_params"
    ),
    param(
        "https://asf.goole.com/mail?url=http%3A%2F%2Ffreasdfuewriter.com%2Fcs%2Fimage%2FCommerciaE.jpg&t=1575955624&ymreqid=733bc9eb-e8f-34cb-1cb5-120010019e00&sig=x2Pa2oOYxanG52s4vyCEFg--~Chttp://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip",
        {"urls": ["https://asf.goole.com/mail?url=http%3A%2F%2Ffreasdfuewriter.com%2Fcs%2Fimage%2FCommerciaE.jpg&t=1575955624&ymreqid=733bc9eb-e8f-34cb-1cb5-120010019e00&sig=x2Pa2oOYxanG52s4vyCEFg--~Chttp://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip",
                  "http://freasdfuewriter.com%2Fcs%2Fimage%2FCommerciaE.jpg&t=1575955624&ymreqid=733bc9eb-e8f-34cb-1cb5-120010019e00&sig=x2Pa2oOYxanG52s4vyCEFg--~Chttp://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip",
                  "http://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip"]},
        {'parse_domain_from_url': False},
        id="domain-issue_104__domains_read_from_percent_encoded_url_query_params__with_options_false"
    ),
    param(
        "https://asf.goole.com/mail?url=http%3A%2F%2Ffreasdfuewriter.com%2Fcs%2Fimage%2FCommerciaE.jpg&t=1575955624&ymreqid=733bc9eb-e8f-34cb-1cb5-120010019e00&sig=x2Pa2oOYxanG52s4vyCEFg--~Chttp://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip",
        {"domains": ["google.com", "freasdfuewriter.com", "uniddloos.zddfdd.org"],
         "urls": ["https://asf.goole.com/mail?url=http%3A%2F%2Ffreasdfuewriter.com%2Fcs%2Fimage%2FCommerciaE.jpg&t=1575955624&ymreqid=733bc9eb-e8f-34cb-1cb5-120010019e00&sig=x2Pa2oOYxanG52s4vyCEFg--~Chttp://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip",
                  "http://freasdfuewriter.com%2Fcs%2Fimage%2FCommerciaE.jpg&t=1575955624&ymreqid=733bc9eb-e8f-34cb-1cb5-120010019e00&sig=x2Pa2oOYxanG52s4vyCEFg--~Chttp://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip",
                  "http://uniddloos.zddfdd.org/CBA0019_file_00002_pdf.zip"]},
        {'parse_from_url_path': False},
        id="domain-issue_104__domains_read_from_percent_encoded_url_query_params__with_options_false_2"
    ),
    param(
        "%2Ffreasdfuewriter.com",
        {"domains": ["2ffreasdfuewriter.com"]},
        {},
        id="domain-percent_encoding_not_unquoted_if_not_in_url",
    ),
    param(
        "freasdfuewriter.com%2F",
        {"domains": ["freasdfuewriter.com"]},
        {},
        id="domain-percent_encoding_not_unquoted_if_not_in_url_2"
    ),
]
