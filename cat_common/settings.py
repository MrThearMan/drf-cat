from typing import Any, Callable

from django.test.signals import setting_changed
from settings_holder import SettingsHolder, reload_settings

from cat_service.typing import NamedTuple

__all__ = [
    "cat_common_settings",
]


SETTING_NAME: str = "CAT_SETTINGS"


class DefaultSettings(NamedTuple):
    PSEUDO_RANDOM_FUNCTION: str = "sha256"
    """Pseudo random function to use for generating keys."""
    IDENTITY_CONVERTER: Callable[[str], Any] = str
    """Function to convert identity value to the required type."""


DEFAULTS = DefaultSettings()._asdict()

cat_common_settings = SettingsHolder(setting_name=SETTING_NAME, defaults=DEFAULTS)

reload_my_settings = reload_settings(SETTING_NAME, cat_common_settings)
setting_changed.connect(reload_my_settings)
