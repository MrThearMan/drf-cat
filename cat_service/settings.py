from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.exceptions import ImproperlyConfigured
from django.test.signals import setting_changed
from settings_holder import SettingsHolder, reload_settings

from cat_common.typing import Any, Callable, NamedTuple

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ed25519


__all__ = [
    "cat_service_settings",
]


SETTING_NAME: str = "CAT_SETTINGS"


class DefaultSettings(NamedTuple):
    VERIFICATION_KEY: str = ""
    """Verification key for this service."""
    VERIFICATION_KEY_URL: str = ""
    """URL where service verification key can be fetched from."""
    CERTIFICATE_URL: str = ""
    """URL where service certificate can be fetched from."""
    SERVICE_TYPE: str = ""
    """Type this service is."""
    SERVICE_NAME: str = ""
    """Name of this service."""
    SERVICE_ORGANIZATION: str = ""
    """Name of the organization this service belongs to."""
    AUTH_SCHEME: str = "CAT"
    """Auth scheme to use in Authorization header."""
    ADDITIONAL_VALID_CAT_HEADERS: list[str] = []
    """Additional valid CAT headers in form: `CAT-{Name-In-Header-Case}`."""
    ADDITIONAL_REQUIRED_CAT_HEADERS: list[str] = []
    """Additional required CAT headers: in form `CAT-{Name-In-Header-Case}`"""
    SERVICE_CERTIFICATE: x509.Certificate | None = None
    """The service certificate."""
    SERVICE_PRIVATE_KEY: ed25519.Ed25519PrivateKey | None = None
    """The service private key."""


DEFAULTS = DefaultSettings()._asdict()


def validate_required(name: str) -> Callable[[Any], None]:
    def validate_value(value: str) -> None:
        if value == "":
            msg = f"`{SETTING_NAME}['{name}']` must be set."
            raise ImproperlyConfigured(msg)

    return validate_value


validators: dict[str, Callable[[Any], None]] = {
    "SERVICE_NAME": validate_required("SERVICE_NAME"),
    "SERVICE_TYPE": validate_required("SERVICE_TYPE"),
    "VERIFICATION_KEY_URL": validate_required("VERIFICATION_KEY_URL"),
    "CERTIFICATE_URL": validate_required("CERTIFICATE_URL"),
}

cat_service_settings = SettingsHolder(
    setting_name=SETTING_NAME,
    defaults=DEFAULTS,
    validators=validators,
)

reload_my_settings = reload_settings(SETTING_NAME, cat_service_settings)
setting_changed.connect(reload_my_settings)
