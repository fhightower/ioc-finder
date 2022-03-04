from pytest import param

TLP_DATA = [
    param("tlp amber and TLP:RED", {"tlp_labels": ["TLP:RED", "TLP:AMBER"]}, {}, id="tlp_1"),
    param("tlp-Amber and TLPRED TlpGreen", {"tlp_labels": ["TLP:RED", "TLP:AMBER", "TLP:GREEN"]}, {}, id="tlp_2"),
]
