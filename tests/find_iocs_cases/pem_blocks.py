from pytest import param

_X509_BLOCK = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n"
    "vQIBADANBgkqhkiGCgKCAQEAvQIBADANBgkqhkiGCgKC\n"
    "-----END CERTIFICATE-----"
)

_PRIVATE_KEY_BLOCK = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEA\n"
    "AoIBAQCqGKukO1De7zhZj6CKwG28ZMUFQAEMLJVOmZTI\n"
    "-----END PRIVATE KEY-----"
)

_PGP_BLOCK = (
    "-----BEGIN PGP MESSAGE-----\n"
    "hQEMA1234567890ABCDEFG/HiJklMnOpQrStUv/Wxyz0\n"
    "-----END PGP MESSAGE-----"
)

_CSR_BLOCK = (
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIICijCCAXICAQAwRTELMAkGA1UEBhMCQVUxEzARBgNV\n"
    "-----END CERTIFICATE REQUEST-----"
)

PEM_DATA = [
    param(
        f"Pinned cert in malware sample:\n{_X509_BLOCK}\nend of report",
        {"x509_certificates": [_X509_BLOCK]},
        {},
        id="x509_pem_certificate",
    ),
    param(
        f"Embedded private key:\n{_PRIVATE_KEY_BLOCK}",
        {"artifacts": [_PRIVATE_KEY_BLOCK]},
        {},
        id="artifact_pem_private_key",
    ),
    param(
        f"Operator's PGP message: {_PGP_BLOCK}",
        {"artifacts": [_PGP_BLOCK]},
        {},
        id="artifact_pem_pgp_message",
    ),
    param(
        f"CSR is not a cert: {_CSR_BLOCK}",
        {"artifacts": [_CSR_BLOCK], "x509_certificates": []},
        {},
        id="artifact_pem_csr_not_certificate",
    ),
    param(
        f"Two together:\n{_X509_BLOCK}\n{_PRIVATE_KEY_BLOCK}",
        {
            "x509_certificates": [_X509_BLOCK],
            "artifacts": [_PRIVATE_KEY_BLOCK],
        },
        {},
        id="x509_and_artifact_together",
    ),
    param(
        # Mismatched BEGIN/END labels — must NOT match.
        "-----BEGIN CERTIFICATE-----\nAAA\n-----END PRIVATE KEY-----",
        {"x509_certificates": [], "artifacts": []},
        {},
        id="pem_mismatched_labels_rejected",
    ),
    param(
        # Unterminated BEGIN — must NOT match.
        "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAA",
        {"x509_certificates": [], "artifacts": []},
        {},
        id="pem_unterminated_rejected",
    ),
    param(
        # PEM body contains a 32-char hex-only run that would otherwise
        # match as an md5. Stripping must prevent that.
        "-----BEGIN CERTIFICATE-----\n"
        "abcdef0123456789abcdef0123456789\n"
        "-----END CERTIFICATE-----",
        {
            "x509_certificates": [
                "-----BEGIN CERTIFICATE-----\nabcdef0123456789abcdef0123456789\n-----END CERTIFICATE-----"
            ],
            "md5s": [],
        },
        {},
        id="pem_body_hex_not_parsed_as_md5",
    ),
]
