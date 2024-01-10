from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as __
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from cat_service.cryptography import create_cat
from cat_service.settings import cat_service_settings

if TYPE_CHECKING:
    from rest_framework.request import Request

    from .typing import Any, Self


User = get_user_model()


__all__ = [
    "CATAuthentication",
    "AuthInfo",
    "get_authorization_header",
    "get_cat_headers",
]


@dataclass(frozen=True, slots=True)
class AuthInfo:
    scheme: str
    creation_key: str
    identity: Any
    info: dict[str, Any]

    @classmethod
    def from_headers(cls, header: str, cat_headers: dict[str, str]) -> Self:
        try:
            scheme, token = header.strip().split()
        except ValueError as error:
            msg = __("Invalid Authorization header. Must be of form: '%(scheme)s <token>'.")
            msg %= {"scheme": cat_service_settings.AUTH_SCHEME}
            raise ValueError(msg) from error

        scheme = scheme.upper()

        if scheme != cat_service_settings.AUTH_SCHEME:
            msg = __("Invalid auth scheme: '%(scheme)s'. Accepted: '%(accepted_scheme)s'.")
            msg %= {"scheme": scheme, "accepted_scheme": cat_service_settings.AUTH_SCHEME}
            raise ValueError(msg) from None

        identity_string: str = cat_headers.get("identity", "").strip()
        if not identity_string:
            msg = __("Missing 'CAT-Identity' header.")
            raise ValueError(msg) from None

        try:
            identity = cat_service_settings.IDENTITY_CONVERTER(identity_string)
        except Exception as error:  # noqa: BLE001
            msg = __("Invalid identity value: '%(identity)s'. Could not convert to required type.")
            msg %= {"identity": identity_string}
            raise ValueError(msg) from error

        info = cls.validate(cat_headers)
        cat = create_cat(**cat_headers)

        if token != cat:
            msg = __("Invalid CAT.")
            raise ValueError(msg) from None

        return cls(scheme=scheme, creation_key=token, identity=identity, info=info)

    @classmethod
    def validate(cls, cat_headers: dict[str, str]) -> dict[str, Any]:
        data: dict[str, Any] = {}
        service_name = cls._validate_service_name(cat_headers)
        if service_name:
            data["service_name"] = service_name
        timestamp = cls._validate_timestamp(cat_headers)
        if timestamp:
            data["timestamp"] = timestamp
        valid_until = cls._validate_valid_until(cat_headers)
        if valid_until:
            data["valid_until"] = valid_until
        return data

    @classmethod
    def _validate_service_name(cls, cat_headers: dict[str, str]) -> str:
        service_name: str = cat_headers.get("service_name", "").strip()
        if not service_name:
            msg = __("Missing 'CAT-Service-Name' header.")
            raise ValueError(msg) from None

        if service_name.casefold() != cat_service_settings.SERVICE_TYPE.casefold():
            msg = __("Request not for this service.")
            raise ValueError(msg) from None

        return service_name

    @classmethod
    def _validate_timestamp(cls, cat_headers: dict[str, str]) -> datetime.datetime | None:
        timestamp: str = cat_headers.get("timestamp", "").strip()
        if not timestamp:
            return None

        try:
            return datetime.datetime.fromisoformat(timestamp)
        except (TypeError, ValueError) as error:
            msg = __("Invalid 'CAT-Timestamp' header. Must be in ISO 8601 format.")
            raise ValueError(msg) from error

    @classmethod
    def _validate_valid_until(cls, cat_headers: dict[str, str]) -> datetime.datetime | None:
        timestamp: str = cat_headers.get("valid_until", "").strip()
        if not timestamp:
            return None

        try:
            valid_until = datetime.datetime.fromisoformat(timestamp)
        except (TypeError, ValueError) as error:
            msg = __("Invalid 'CAT-Valid-Until' header. Must be in ISO 8601 format.")
            raise ValueError(msg) from error

        if valid_until.tzinfo is None:
            valid_until.replace(tzinfo=datetime.UTC)

        if valid_until.astimezone(datetime.UTC) < datetime.datetime.now(tz=datetime.UTC):
            msg = __("'CAT-Valid-Until' header indicates that the request is no longer valid.")
            raise ValueError(msg)

        return valid_until


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
    """

    auth_scheme: str = cat_service_settings.AUTH_SCHEME
    auth_info_class: type[AuthInfo] = AuthInfo

    def authenticate(self, request: Request) -> tuple[User, None] | None:
        try:
            auth_header = get_authorization_header(request)
        except ValueError as error:
            raise AuthenticationFailed(error.args[0]) from error

        try:
            cat_headers = get_cat_headers(request)
        except ValueError as error:
            raise AuthenticationFailed(error.args[0]) from error

        try:
            auth_info = self.auth_info_class.from_headers(auth_header, cat_headers)
        except ValueError as error:
            raise AuthenticationFailed(error.args[0]) from error

        try:
            user = self.get_user(auth_info)
        except Exception as error:  # noqa: BLE001 pragma: no cover
            msg = __("User does not exist.")
            raise AuthenticationFailed(msg) from error

        return user, None

    def get_user(self, auth_info: AuthInfo) -> User:
        return User.objects.get(pk=auth_info.identity)

    def authenticate_header(self, request: Request) -> str:
        return self.auth_scheme


def get_authorization_header(request: Request) -> str:
    """
    Return request's 'Authorization' header as a string.

    :raises ValueError: The header is not valid ASCII.
    """
    authorization: str | bytes = request.META.get("HTTP_AUTHORIZATION", "")
    if isinstance(authorization, bytes):
        try:
            return authorization.decode()
        except UnicodeError as error:
            msg = __("Invalid Authorization header. Should not contain non-ASCII characters.")
            raise ValueError(msg) from error
    return authorization


def get_cat_headers(request: Request) -> dict[str, str]:
    """
    Return additional headers sent for CAT authentication.

    :raises ValueError: Invalid header found.
    """
    headers: dict[str, str] = {}
    for header, value in request.META.items():
        if not header.startswith("HTTP_CAT_"):
            continue

        header_key = header.removeprefix("HTTP_CAT_").lower()
        header_key_formatted = "-".join(value.capitalize() for value in header_key.split("_"))

        if isinstance(value, bytes):
            try:
                value = value.decode()  # noqa: PLW2901
            except UnicodeError as error:
                msg = __("Invalid CAT header 'CAT-%(header)s'. Should not contain non-ASCII characters.")
                msg %= {"header": header_key_formatted}
                raise ValueError(msg) from error

        if header_key not in cat_service_settings.VALID_CAT_HEADERS:
            msg = __("Unrecognized CAT header 'CAT-%(header)s'.")
            msg %= {"header": header_key_formatted}
            raise ValueError(msg)

        headers[header_key] = value
    return headers
