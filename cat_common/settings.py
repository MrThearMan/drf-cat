from __future__ import annotations

from typing import Any, Callable

from django.core.exceptions import ImproperlyConfigured
from django.test.signals import setting_changed
from settings_holder import SettingsHolder, reload_settings

from cat_common.typing import NamedTuple

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
