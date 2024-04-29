from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as __
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from cat_common import error_codes, known_headers
from cat_common.utils import get_authorization_header
from cat_service.cryptography import create_cat
from cat_service.settings import cat_service_settings
from cat_service.utils import (
    as_human_readable_list,
    from_cat_header_name,
    get_required_cat_headers,
    get_valid_cat_headers,
    to_cat_header_name,
)
from cat_service.validation import (
    validate_identity,
    validate_nonce,
    validate_service_name,
    validate_timestamp,
    validate_valid_until,
)

if TYPE_CHECKING:
    from rest_framework.request import Request

    from cat_common.typing import Any, Callable, ClassVar, HeaderKey, HeaderValue

User = get_user_model()


__all__ = [
    "CATAuthentication",
    "get_cat_headers",
]


class CATAuthentication(BaseAuthentication):
    """
    CAT authentication.

    Authorization header format: <auth_scheme> <cat>

    auth_scheme: Auth scheme as set by the `AUTH_SCHEME` setting. Default: `CAT`.
    cat: Users CAT for the request.

    Additional headers:

    CAT-Identity: Required. The user's identity. Default is the user's primary key.
    CAT-Service-Name: Required. The name of the service.
    CAT-Timestamp: The time the request was sent.
    CAT-Valid-Until: The time until the request is valid.
    CAT-Nonce: A random nonce that can be used for replay attack prevention.
    """

    auth_scheme: str = cat_service_settings.AUTH_SCHEME

    header_validators: ClassVar[dict[str, Callable[[str], Any]]] = {
        known_headers.IDENTITY: validate_identity,
        known_headers.SERVICE_NAME: validate_service_name,
        known_headers.TIMESTAMP: validate_timestamp,
        known_headers.VALID_UNTIL: validate_valid_until,
        known_headers.NONCE: validate_nonce,
    }

    def authenticate(self, request: Request) -> tuple[User, None] | None:
        scheme, token = get_authorization_header(request)
        cat_headers = get_cat_headers(request)

        self.validate_auth_scheme(scheme)
        cat_info = self.validate_cat_headers(cat_headers)
        self.validate_cat_token(token, cat_headers)

        try:
            user = self.get_user(cat_info)
        except Exception as error:  # pragma: no cover
            msg = __("User does not exist.")
            raise AuthenticationFailed(msg, code=error_codes.USER_DOES_NOT_EXIST) from error

        return user, None

    def validate_auth_scheme(self, scheme: str) -> None:
        if scheme.casefold() != self.auth_scheme.casefold():
            msg = __("Invalid auth scheme: '%(scheme)s'. Accepted: '%(accepted_scheme)s'.")
            msg %= {"scheme": scheme, "accepted_scheme": self.auth_scheme}
            raise AuthenticationFailed(msg, code=error_codes.INVALID_AUTH_SCHEME) from None

    def validate_cat_headers(self, cat_headers: dict[HeaderKey, HeaderValue]) -> dict[HeaderKey, Any]:
        data: dict[HeaderKey, Any] = {}
        required_headers = get_required_cat_headers()
        valid_headers = get_valid_cat_headers()

        for header_key, header_value in cat_headers.items():
            if header_key not in valid_headers:
                msg = __("Unrecognized CAT header: '%(header)s'.")
                msg %= {"header": header_key}
                raise AuthenticationFailed(msg, code=error_codes.UNRECOGNIZED_CAT_HEADER) from None

            validator = self.header_validators.get(header_key)
            if validator is None:
                msg = __("Missing validation function for header: '%(header)s'.") % {"header": header_key}
                raise AuthenticationFailed(msg, code=error_codes.MISSING_VALIDATION_FUNCTION) from None

            data[header_key] = validator(header_value)
            required_headers.discard(header_key)

        if required_headers:
            msg = __("Missing required headers: %(required_headers)s.") % {
                "required_headers": as_human_readable_list(required_headers),
            }
            raise AuthenticationFailed(msg, code=error_codes.MISSING_REQUIRED_HEADERS) from None

        return data

    def validate_cat_token(self, token: str, cat_headers: dict[HeaderKey, HeaderValue]) -> None:
        try:
            cat = create_cat(**{from_cat_header_name(key): value for key, value in cat_headers.items()})
        except Exception as error:  # pragma: no cover
            raise AuthenticationFailed(str(error), code=error_codes.SERVICE_SETUP_ERROR) from error

        if token != cat:
            msg = __("Invalid CAT.")
            raise AuthenticationFailed(msg, code=error_codes.INVALID_CAT) from None

    def get_user(self, cat_info: dict[HeaderKey, Any]) -> User:
        return User.objects.get(pk=cat_info.get(known_headers.IDENTITY))

    def authenticate_header(self, request: Request) -> str:
        return self.auth_scheme


def get_cat_headers(request: Request) -> dict[HeaderKey, HeaderValue]:
    """
    Return additional headers sent for CAT authentication.

    :raises AuthenticationFailed: Invalid header found.
    """
    headers: dict[HeaderKey, HeaderValue] = {}
    for header, value in request.META.items():
        if not header.startswith("HTTP_CAT_"):
            continue

        header_key = to_cat_header_name(header.removeprefix("HTTP_CAT_"))

        if isinstance(value, bytes):
            try:
                value = value.decode()  # noqa: PLW2901
            except UnicodeError as error:
                msg = __("Invalid CAT header '%(header)s'. Should not contain non-ASCII characters.")
                msg %= {"header": header_key}
                raise AuthenticationFailed(msg, code=error_codes.INVALID_CAT_HEADER) from error

        headers[header_key] = value
    return headers
