from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as __
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission

from cat_ca.validation import validate_client_certificate
from cat_common import error_codes
from cat_common.cryptography import deserialize_certificate
from cat_common.utils import get_authorization_header

User = get_user_model()

if TYPE_CHECKING:
    from rest_framework.request import Request
    from rest_framework.views import APIView

__all__ = [
    "CertificatePermission",
]


class CertificatePermission(BasePermission):
    def has_permission(self, request: Request, view: APIView) -> bool:
        _, token = get_authorization_header(request)

        try:
            certificate = deserialize_certificate(token)
        except Exception as error:  # noqa: BLE001 pragma: no cover
            msg = __("Invalid certificate.")
            raise AuthenticationFailed(msg, code=error_codes.INVALID_CERTIFICATE) from error

        try:
            validate_client_certificate(certificate)
        except ValueError as error:  # pragma: no cover
            raise AuthenticationFailed(error.args[0], code=error_codes.INVALID_CERTIFICATE) from error

        return True
