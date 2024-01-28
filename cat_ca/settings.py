from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from django.core.exceptions import ImproperlyConfigured
from django.test.signals import setting_changed
from settings_holder import SettingsHolder, reload_settings

from cat_common.typing import Any, Callable, NamedTuple

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ed25519


__all__ = [
    "cat_ca_settings",
]


SETTING_NAME: str = "CAT_SETTINGS"


class DefaultSettings(NamedTuple):
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


DEFAULTS = DefaultSettings()._asdict()


def validate_required(name: str) -> Callable[[Any], None]:
    def validate_value(value: str) -> None:  # pragma: no cover
        if value == "":
            msg = f"`{SETTING_NAME}['{name}']` must be set."
            raise ImproperlyConfigured(msg)

    return validate_value


validators: dict[str, Callable[[Any], None]] = {
    "CAT_ROOT_KEY": validate_required("CAT_ROOT_KEY"),
}

cat_ca_settings = SettingsHolder(
    setting_name=SETTING_NAME,
    defaults=DEFAULTS,
    validators=validators,
)

reload_my_settings = reload_settings(SETTING_NAME, cat_ca_settings)
setting_changed.connect(reload_my_settings)
