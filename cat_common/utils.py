from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography import x509
from django.utils.translation import gettext_lazy as __
from rest_framework.exceptions import AuthenticationFailed

from cat_common import error_codes

if TYPE_CHECKING:
    from rest_framework.request import Request


__all__ = [
    "get_authorization_header",
    "get_basic_constraints",
    "get_common_name",
    "get_key_usage",
]


def get_authorization_header(request: Request) -> tuple[str, str]:
    """
    Return request's 'Authorization' header, split into the scheme and token.

    :raises AuthenticationFailed: The header is invalid or missing.
    """
    authorization: str | bytes = request.META.get("HTTP_AUTHORIZATION", "")
    if not authorization:
        msg = __("Missing Authorization header.")
        raise AuthenticationFailed(msg, code=error_codes.MISSING_AUTH_HEADER)

    if isinstance(authorization, bytes):
        try:
            authorization = authorization.decode()
        except UnicodeError as error:
            msg = __("Invalid Authorization header. Should not contain non-ASCII characters.")
            raise AuthenticationFailed(msg, code=error_codes.INVALID_AUTH_HEADER) from error

    try:
        scheme, token = authorization.strip().split()
    except ValueError as error:
        msg = __("Invalid Authorization header. Must be of form: '<scheme> <token>'.")
        raise AuthenticationFailed(msg, code=error_codes.INVALID_AUTH_HEADER) from error

    return scheme, token


def get_common_name(name: x509.Name) -> str | None:
    common_names = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not common_names:  # pragma: no cover
        return None
    return str(common_names[0].value)


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
