from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as __
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from cat_service.cryptography import hmac
from cat_service.settings import cat_service_settings
from cat_service.typing import AuthInfo

if TYPE_CHECKING:
    from rest_framework.request import Request


User = get_user_model()


__all__ = [
    "CATAuthentication",
]


class CATAuthentication(BaseAuthentication):
    """
    CAT authentication.

    Authorization header format: <auth_scheme> <token>, <identity_key>=<identity_value>

    auth_scheme: Auth scheme as set by the `AUTH_SCHEME` setting. Default: `CAT`.
    token: Users CAT creation key for this service.
    identity_key: Identity key as set by the `IDENTITY_KEY` setting. Default: `pk`.
    identity_value: Value corresponding to the identity key. Default: User's primary key.
    """

    auth_scheme = cat_service_settings.AUTH_SCHEME
    identity_key = cat_service_settings.IDENTITY_KEY

    def authenticate(self, request: Request) -> tuple[User, None] | None:
        try:
            header = get_authorization_header(request).decode()
        except UnicodeError as error:
            msg = __("Invalid token header. Token string should not contain invalid characters.")
            raise AuthenticationFailed(msg) from error

        auth_info = self.validate_authorization_header(header)

        try:
            user = self.get_user(auth_info)
        except Exception as error:  # noqa:BLE001 pragma: no cover
            msg = __("User does not exist.")
            raise AuthenticationFailed(msg) from error

        return user, None

    def validate_authorization_header(self, header: str) -> AuthInfo:
        try:
            auth, identity = header.split(",")
        except ValueError as error:
            msg = __("Invalid token header. Must be of form: '%(scheme)s <token>, %(identity)s=<identity_value>'.")
            msg %= {"scheme": self.auth_scheme, "identity": self.identity_key}
            raise AuthenticationFailed(msg) from error

        try:
            scheme, token = auth.strip().split()
        except ValueError as error:
            msg = __("Invalid auth token. Must be of form: '%(scheme)s <token>'.")
            msg %= {"scheme": self.auth_scheme}
            raise AuthenticationFailed(msg) from error

        scheme = scheme.upper()

        if scheme != self.auth_scheme:
            msg = __("Invalid auth scheme: '%(scheme)s'. Accepted: '%(accepted_scheme)s'.")
            msg %= {"scheme": scheme, "accepted_scheme": self.auth_scheme}
            raise AuthenticationFailed(msg) from None

        try:
            identity_key, identity_value = identity.split("=")
        except ValueError as error:
            msg = __("Invalid identity. Must be of form: '%(identity)s=<identity_value>'.")
            msg %= {"scheme": self.auth_scheme, "identity": self.identity_key}
            raise AuthenticationFailed(msg) from error

        identity_key = identity_key.strip().lower()
        identity_value = identity_value.strip()

        if identity_key != self.identity_key:
            msg = __("Invalid identity key: '%(key)s'. Accepted: '%(accepted_key)s'.")
            msg %= {"key": identity_key, "accepted_key": self.identity_key}
            raise AuthenticationFailed(msg) from None

        if cat_service_settings.VERIFICATION_KEY == "":
            msg = __("Service not set up correctly.")
            raise AuthenticationFailed(msg) from None

        if token != hmac(msg=identity_value, key=cat_service_settings.VERIFICATION_KEY):
            msg = __("Invalid token.")
            raise AuthenticationFailed(msg) from None

        return AuthInfo(scheme=scheme, token=token, identity_key=identity_key, identity_value=identity_value)

    def get_user(self, auth_info: AuthInfo) -> User:
        return User.objects.get(**{auth_info.identity_key: auth_info.identity_value})

    def authenticate_header(self, request: Request) -> str:
        return self.auth_scheme
