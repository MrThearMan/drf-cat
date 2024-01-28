import datetime

from cryptography import x509

from cat_ca.settings import cat_ca_settings

__all__ = [
    "validate_csr",
    "validate_client_certificate",
    "get_basic_constraints",
    "get_key_usage",
]


def validate_csr(csr: x509.CertificateSigningRequest) -> None:
    if not csr.is_signature_valid:  # pragma: no cover
        msg = "CSR signature is invalid."
        raise ValueError(msg)

    # TODO: Validate `csr.subject` exists.
    # TODO: Possible challenges?


def validate_client_certificate(client_certificate: x509.Certificate) -> None:
    if cat_ca_settings.CA_CERTIFICATE is None:  # pragma: no cover
        msg = "CA does not have a certificate, cannot validate client certificate."
        raise ValueError(msg)

    # UTC time.
    now = datetime.datetime.now()  # noqa: DTZ005

    try:
        client_certificate.verify_directly_issued_by(cat_ca_settings.CA_CERTIFICATE)
    except ValueError as error:  # pragma: no cover
        msg = "Certificate is not signed by this CA."
        raise ValueError(msg) from error

    if client_certificate.not_valid_before >= now:  # pragma: no cover
        msg = "Certificate is not valid yet."
        raise ValueError(msg)

    if client_certificate.not_valid_after <= now:  # pragma: no cover
        msg = "Certificate is no longer valid."
        raise ValueError(msg)

    basic_constraints = get_basic_constraints(client_certificate)
    if basic_constraints is None:  # pragma: no cover
        msg = "Certificate is missing `Basic Constraints` extension."
        raise ValueError(msg)
    if basic_constraints.ca:  # pragma: no cover
        msg = "Certificate is a CA certificate."
        raise ValueError(msg)

    key_usage = get_key_usage(client_certificate)
    if key_usage is None:  # pragma: no cover
        msg = "Certificate is missing the `Key Usage` extension."
        raise ValueError(msg)
    if not key_usage.digital_signature:  # pragma: no cover
        msg = "Certificate cannot be used for digital signatures."
        raise ValueError(msg)

    # TODO: Validate `client_certificate.subject` exists.


def get_basic_constraints(certificate: x509.Certificate) -> x509.BasicConstraints | None:
    try:
        extension = certificate.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
    except x509.ExtensionNotFound:  # pragma: no cover
        return None
    return extension.value  # type: ignore[return-value]


def get_key_usage(certificate: x509.Certificate) -> x509.KeyUsage | None:
    try:
        extension = certificate.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
    except x509.ExtensionNotFound:  # pragma: no cover
        return None
    return extension.value  # type: ignore[return-value]
