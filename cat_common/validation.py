from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from rest_framework.exceptions import AuthenticationFailed

from cat_common import error_codes
from cat_common.utils import get_basic_constraints, get_key_usage

if TYPE_CHECKING:
    from cryptography import x509


__all__ = [
    "validate_basic_constraints",
    "validate_key_usage",
    "validate_valid_period",
]


def validate_valid_period(certificate: x509.Certificate) -> None:
    now = datetime.datetime.now(tz=datetime.timezone.utc)

    if certificate.not_valid_before_utc >= now:  # pragma: no cover
        msg = "Certificate is not valid yet."
        raise AuthenticationFailed(msg, code=error_codes.CERTIFICATE_NOT_VALID_YET)

    if certificate.not_valid_after_utc <= now:  # pragma: no cover
        msg = "Certificate is no longer valid."
        raise AuthenticationFailed(msg, code=error_codes.CERTIFICATE_NOT_VALID_ANYMORE)


def validate_basic_constraints(client_certificate: x509.Certificate) -> None:
    basic_constraints = get_basic_constraints(client_certificate)
    if basic_constraints is None:  # pragma: no cover
        msg = "Certificate is missing `Basic Constraints` extension."
        raise AuthenticationFailed(msg, code=error_codes.MISSING_BASIC_CONSTRAINTS)
    if basic_constraints.ca:  # pragma: no cover
        msg = "Certificate is a CA certificate."
        raise AuthenticationFailed(msg, code=error_codes.CANT_BE_A_CA)


def validate_key_usage(client_certificate: x509.Certificate) -> None:
    key_usage = get_key_usage(client_certificate)
    if key_usage is None:  # pragma: no cover
        msg = "Certificate is missing the `Key Usage` extension."
        raise AuthenticationFailed(msg, code=error_codes.MISSING_KEY_USAGE)
    if not key_usage.digital_signature:  # pragma: no cover
        msg = "Certificate cannot be used for digital signatures."
        raise AuthenticationFailed(msg, code=error_codes.CANT_BE_USED_FOR_DIGITAL_SIGNATURES)
