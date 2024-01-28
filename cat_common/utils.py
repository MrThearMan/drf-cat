from __future__ import annotations

from typing import TYPE_CHECKING

from django.utils.translation import gettext_lazy as __
from rest_framework.exceptions import AuthenticationFailed

from cat_common import error_codes

if TYPE_CHECKING:
    from rest_framework.request import Request


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
