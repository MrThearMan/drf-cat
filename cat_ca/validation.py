from cryptography import x509


def validate_csr(csr: x509.CertificateSigningRequest) -> None:
    if not csr.is_signature_valid:  # pragma: no cover
        msg = "CSR signature is invalid."
        raise ValueError(msg)

    # TODO: Validate `csr.subject` exists.
