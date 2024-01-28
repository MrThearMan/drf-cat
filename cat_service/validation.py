from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Any

from django.utils.translation import gettext_lazy as __
from rest_framework.exceptions import AuthenticationFailed

from cat_service import error_codes
from cat_service.settings import cat_service_settings

if TYPE_CHECKING:
    from .typing import Any

__all__ = [
    "validate_identity",
    "validate_service_name",
    "validate_timestamp",
    "validate_valid_until",
    "validate_nonce",
]


def validate_identity(identity: str) -> Any:
    try:
        return cat_service_settings.IDENTITY_CONVERTER(identity.strip())
    except Exception as error:  # noqa: BLE001
        msg = __("Invalid identity value: '%(identity)s'. Could not convert to required type.")
        msg %= {"identity": identity}
        raise AuthenticationFailed(msg, code=error_codes.INVALID_IDENTITY) from error


def validate_service_name(service_name: str) -> str:
    if service_name.casefold() != cat_service_settings.SERVICE_TYPE.casefold():
        msg = __("Request not for this service.")
        raise AuthenticationFailed(msg, code=error_codes.WRONG_SERVICE) from None
    return service_name


def validate_timestamp(timestamp: str) -> datetime.datetime:
    try:
        return datetime.datetime.fromisoformat(timestamp)
    except (TypeError, ValueError) as error:
        msg = __("Invalid 'CAT-Timestamp' header. Must be in ISO 8601 format.")
        raise AuthenticationFailed(msg, code=error_codes.INVALID_TIMESTAMP) from error


def validate_valid_until(timestamp: str) -> datetime.datetime:
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


def validate_nonce(nonce: str) -> Any:
    # A hook for validate a nonce. A service may consider caching nonce's and checking that
    # a nonce has not been used before to prevent replay attacks.
    return nonce
