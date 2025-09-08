from __future__ import annotations

import datetime
from typing import TYPE_CHECKING, Any, Callable

from django.core.exceptions import ImproperlyConfigured
from django.test.signals import setting_changed
from settings_holder import SettingsHolder, reload_settings

from cat_common.typing import NamedTuple

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ed25519


__all__ = [
    "cat_common_settings",
]


SETTING_NAME: str = "CAT_SETTINGS"


class DefaultSettings(NamedTuple):
    CA_NAME: str = ""
    """Name of the Certificate Authority that signs certificates."""
    PSEUDO_RANDOM_FUNCTION: str = "sha256"
    """Pseudo random function to use for generating keys."""
    IDENTITY_CONVERTER: Callable[[str], Any] = str
    """Function to convert identity value to the required type."""
    CA_ORGANIZATION: str = ""
    """Name of the CA Organization."""
    CAT_ROOT_KEY: str = ""
    """Root key for CAT. Should be kept secret."""
    CA_CERTIFICATE_VALIDITY_PERIOD: datetime.timedelta = datetime.timedelta(days=10)
    """How long the CA certificate is valid for."""
    CLIENT_CERTIFICATE_VALIDITY_PERIOD: datetime.timedelta = datetime.timedelta(days=10)
    """How long the client certificate is valid for."""
    LEEWAY: datetime.timedelta = datetime.timedelta(seconds=1)
    """How much leeway to give for validity before period."""
    CA_CERTIFICATE: x509.Certificate | None = None
    """The CA certificate."""
    CA_PRIVATE_KEY: ed25519.Ed25519PrivateKey | None = None
    """The CA private key."""
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
    def validate_value(value: str) -> None:  # pragma: no cover
        if value == "":
            msg = f"`{SETTING_NAME}['{name}']` must be set."
            raise ImproperlyConfigured(msg)

    return validate_value


validators: dict[str, Callable[[Any], None]] = {
    "CA_NAME": validate_required("CA_NAME"),
}

cat_common_settings = SettingsHolder(
    setting_name=SETTING_NAME,
    defaults=DEFAULTS,
    validators=validators,
)

reload_my_settings = reload_settings(SETTING_NAME, cat_common_settings)
setting_changed.connect(reload_my_settings)
