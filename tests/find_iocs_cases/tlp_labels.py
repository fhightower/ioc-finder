def case_tlp_label_len_2():
    text = "tlp amber and TLP:RED"
    results = {"tlp_labels": ["TLP:RED", "TLP:AMBER"]}
    return text, results


def case_tlp_label_len_3():
    text = "tlp-Amber and TLPRED TlpGreen"
    results = {"tlp_labels": ["TLP:RED", "TLP:AMBER", "TLP:GREEN"]}
    return text, results
