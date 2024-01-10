from django.core.exceptions import ImproperlyConfigured
from django.test.signals import setting_changed
from settings_holder import SettingsHolder, reload_settings

from cat_ca.typing import NamedTuple

__all__ = [
    "cat_ca_settings",
]


SETTING_NAME: str = "CAT_SETTINGS"


class DefaultSettings(NamedTuple):
    CAT_ROOT_KEY: str = ""
    """Root key for CAT. Should be kept secret."""
    PSEUDO_RANDOM_FUNCTION: str = "sha256"
    """Pseudo random function to use for generating keys."""
    AUTH_SCHEME: str = "CAT"
    """Auth scheme to use in Authorization header."""


DEFAULTS = DefaultSettings()._asdict()

IMPORT_STRINGS: set[bytes | str] = set()

REMOVED_SETTINGS: set[str] = set()

cat_ca_settings = SettingsHolder(
    setting_name=SETTING_NAME,
    defaults=DEFAULTS,
    import_strings=IMPORT_STRINGS,
    removed_settings=REMOVED_SETTINGS,
)

if cat_ca_settings.CAT_ROOT_KEY == "":  # pragma: no cover
    msg = f"`{SETTING_NAME}['CAT_ROOT_KEY']` must be set."
    raise ImproperlyConfigured(msg)

reload_my_settings = reload_settings(SETTING_NAME, cat_ca_settings)
setting_changed.connect(reload_my_settings)
