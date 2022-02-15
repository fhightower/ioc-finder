def case_multiple_hashes_simple():
    text = "{} {} {} {} {}".format('A' * 32, 'a' * 32, 'b' * 40, 'c' * 64, 'd' * 128)
    results = {"tlp_labels": ["TLP:RED", "TLP:AMBER"]}
    # TODO
    return text, results
