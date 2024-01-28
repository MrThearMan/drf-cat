from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as __
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission

from cat_ca.validation import validate_issuer
from cat_common import error_codes
from cat_common.cryptography import deserialize_certificate
from cat_common.utils import get_authorization_header
from cat_common.validation import validate_basic_constraints, validate_key_usage, validate_valid_period

User = get_user_model()

if TYPE_CHECKING:
    from cryptography import x509
    from rest_framework.request import Request
    from rest_framework.views import APIView

    from cat_common.typing import Any, Callable, ClassVar


__all__ = [
    "CertificatePermission",
]


class CertificatePermission(BasePermission):
    """Check that the request contains a valid certificate."""

    certificate_validators: ClassVar[list[Callable[[x509.Certificate], Any]]] = [
        validate_issuer,
        validate_valid_period,
        validate_basic_constraints,
        validate_key_usage,
        # TODO: Validate `client_certificate.subject` exists.
    ]

    def has_permission(self, request: Request, view: APIView) -> bool:
        _, token = get_authorization_header(request)

        try:
            certificate = deserialize_certificate(token)
        except Exception as error:  # noqa: BLE001 pragma: no cover
            msg = __("Invalid certificate.")
            raise AuthenticationFailed(msg, code=error_codes.INVALID_CERTIFICATE) from error

        for validator in self.certificate_validators:
            validator(certificate)

        return True
