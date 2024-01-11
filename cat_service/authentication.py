from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.utils.translation import gettext_lazy as __
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from cat_service.cryptography import create_cat
from cat_service.settings import cat_service_settings

from . import error_codes, known_headers
from .utils import (
    as_human_readable_list,
    from_cat_header_name,
    get_required_cat_headers,
    get_valid_cat_headers,
    to_cat_header_name,
)

if TYPE_CHECKING:
    from django.contrib.auth import get_user_model
    from rest_framework.request import Request

    from .typing import Any, HeaderKey, HeaderValue, Self, Validator

    User = get_user_model()


__all__ = [
    "CATAuthentication",
    "AuthInfo",
    "get_authorization_header",
    "get_cat_headers",
]


@dataclass(frozen=True, slots=True)
class AuthInfo:
    """Class for holding authentication information."""

    scheme: str
    creation_key: str
    identity: Any
    info: dict[str, Any]

    @classmethod
    def from_headers(cls, authorization_header: str, cat_headers: dict[HeaderKey, HeaderValue]) -> Self:
        """Validate authentication header with CAT headers and create an AuthInfo instance."""
        try:
            scheme, token = authorization_header.strip().split()
        except ValueError as error:
            msg = __("Invalid Authorization header. Must be of form: '%(scheme)s <token>'.")
            msg %= {"scheme": cat_service_settings.AUTH_SCHEME}
            raise AuthenticationFailed(msg, code=error_codes.INVALID_AUTH_HEADER) from error

        if scheme.casefold() != cat_service_settings.AUTH_SCHEME.casefold():
            msg = __("Invalid auth scheme: '%(scheme)s'. Accepted: '%(accepted_scheme)s'.")
            msg %= {"scheme": scheme, "accepted_scheme": cat_service_settings.AUTH_SCHEME}
            raise AuthenticationFailed(msg, code=error_codes.INVALID_AUTH_SCHEME) from None

        info = cls.validate(cat_headers)
        cat = create_cat(**{from_cat_header_name(key): value for key, value in cat_headers.items()})

        if token != cat:
            msg = __("Invalid CAT.")
            raise AuthenticationFailed(msg, code=error_codes.INVALID_CAT) from None

        identity = info.pop(known_headers.IDENTITY)
        return cls(scheme=scheme.upper(), creation_key=token, identity=identity, info=info)

    @classmethod
    def validate(cls, cat_headers: dict[HeaderKey, HeaderValue]) -> dict[HeaderKey, Any]:
        data: dict[HeaderKey, Any] = {}
        required_headers = get_required_cat_headers()
        valid_headers = get_valid_cat_headers()

        for header_key, header_value in cat_headers.items():
            if header_key not in valid_headers:
                msg = __("Unrecognized CAT header: '%(header)s'.")
                msg %= {"header": header_key}
                raise AuthenticationFailed(msg, code=error_codes.UNRECOGNIZED_CAT_HEADER) from None

            validator: Validator | None = getattr(cls, f"validate_{from_cat_header_name(header_key)}", None)
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

    @classmethod
    def validate_identity(cls, identity: str) -> Any:
        try:
            return cat_service_settings.IDENTITY_CONVERTER(identity.strip())
        except Exception as error:  # noqa: BLE001
            msg = __("Invalid identity value: '%(identity)s'. Could not convert to required type.")
            msg %= {"identity": identity}
            raise AuthenticationFailed(msg, code=error_codes.INVALID_IDENTITY) from error

    @classmethod
    def validate_service_name(cls, service_name: str) -> str:
        if service_name.casefold() != cat_service_settings.SERVICE_TYPE.casefold():
            msg = __("Request not for this service.")
            raise AuthenticationFailed(msg, code=error_codes.WRONG_SERVICE) from None
        return service_name

    @classmethod
    def validate_timestamp(cls, timestamp: str) -> datetime.datetime:
        try:
            return datetime.datetime.fromisoformat(timestamp)
        except (TypeError, ValueError) as error:
            msg = __("Invalid 'CAT-Timestamp' header. Must be in ISO 8601 format.")
            raise AuthenticationFailed(msg, code=error_codes.INVALID_TIMESTAMP) from error

    @classmethod
    def validate_valid_until(cls, timestamp: str) -> datetime.datetime:
        try:
            valid_until = datetime.datetime.fromisoformat(timestamp)
        except (TypeError, ValueError) as error:
            msg = __("Invalid 'CAT-Valid-Until' header. Must be in ISO 8601 format.")
            raise AuthenticationFailed(msg, code=error_codes.INVALID_VALID_UNTIL) from error

        if valid_until.tzinfo is None:
            valid_until.replace(tzinfo=datetime.timezone.utc)

        if valid_until.astimezone(datetime.timezone.utc) < datetime.datetime.now(tz=datetime.timezone.utc):
            msg = __("'CAT-Valid-Until' header indicates that the request is no longer valid.")
            raise AuthenticationFailed(msg, code=error_codes.CAT_EXPIRED) from None

        return valid_until

    @classmethod
    def validate_nonce(cls, nonce: str) -> Any:
        # A hook for validate a nonce. A service may consider caching nonce's and checking that
        # a nonce has not been used before to prevent replay attacks.
        return nonce


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
    auth_info_class: type[AuthInfo] = AuthInfo

    def authenticate(self, request: Request) -> tuple[User, None] | None:
        authorization_header = get_authorization_header(request)
        cat_headers = get_cat_headers(request)
        auth_info = self.auth_info_class.from_headers(authorization_header, cat_headers)

        try:
            user = self.get_user(auth_info)
        except Exception as error:  # noqa: BLE001 pragma: no cover
            msg = __("User does not exist.")
            raise AuthenticationFailed(msg, code=error_codes.USER_DOES_NOT_EXIST) from error

        return user, None

    def get_user(self, auth_info: AuthInfo) -> User:
        return User.objects.get(pk=auth_info.identity)

    def authenticate_header(self, request: Request) -> str:
        return self.auth_scheme


def get_authorization_header(request: Request) -> str:
    """
    Return request's 'Authorization' header as a string.

    :raises AuthenticationFailed: The header is not valid ASCII.
    """
    authorization: str | bytes = request.META.get("HTTP_AUTHORIZATION", "")
    if isinstance(authorization, bytes):
        try:
            return authorization.decode()
        except UnicodeError as error:
            msg = __("Invalid Authorization header. Should not contain non-ASCII characters.")
            raise AuthenticationFailed(msg, code=error_codes.INVALID_AUTH_HEADER) from error
    return authorization


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
