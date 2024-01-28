from __future__ import annotations

from typing import TYPE_CHECKING

from rest_framework.exceptions import AuthenticationFailed

from cat_ca.settings import cat_ca_settings
from cat_common import error_codes

if TYPE_CHECKING:
    from cryptography import x509


__all__ = [
    "validate_issuer",
]


def validate_issuer(client_certificate: x509.Certificate) -> None:
    if cat_ca_settings.CA_CERTIFICATE is None:  # pragma: no cover
        msg = "CA does not have a certificate, cannot validate client certificate."
        raise AuthenticationFailed(msg, code=error_codes.MISSING_CA_CERTIFICATE)

    try:
        client_certificate.verify_directly_issued_by(cat_ca_settings.CA_CERTIFICATE)
    except ValueError as error:  # pragma: no cover
        msg = "Certificate is not signed by this CA."
        raise AuthenticationFailed(msg, code=error_codes.NOT_DIRECTLY_ISSUED_BY_CA) from error
