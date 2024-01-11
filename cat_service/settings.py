from typing import Any, Callable

from django.test.signals import setting_changed
from settings_holder import SettingsHolder, reload_settings

from cat_service.typing import NamedTuple

__all__ = [
    "cat_service_settings",
]


SETTING_NAME: str = "CAT_SETTINGS"


class DefaultSettings(NamedTuple):
    VERIFICATION_KEY: str = ""
    """Verification key for this service."""
    VERIFICATION_KEY_SETUP: str = "cat_service.setup.get_verification_key"
    """Function that sets up the verification key for this service."""
    SERVICE_TYPE: str = ""
    """Type this service is."""
    SERVICE_NAME: str = ""
    """Name of this service."""
    VERIFICATION_KEY_URL: str = ""
    """URL to the where service verification key can be fetched from."""
    PSEUDO_RANDOM_FUNCTION: str = "sha256"
    """Pseudo random function to use for generating keys."""
    AUTH_SCHEME: str = "CAT"
    """Auth scheme to use in Authorization header."""
    ADDITIONAL_VALID_CAT_HEADERS: list[str] = []
    """Additional valid CAT headers in form: `CAT-{Name-In-Header-Case}`."""
    ADDITIONAL_REQUIRED_CAT_HEADERS: list[str] = []
    """Additional required CAT headers: in form `CAT-{Name-In-Header-Case}`"""
    IDENTITY_CONVERTER: Callable[[str], Any] = str
    """Function to convert identity value to the required type."""


DEFAULTS = DefaultSettings()._asdict()

IMPORT_STRINGS: set[bytes | str] = {
    b"VERIFICATION_KEY_SETUP",
}

REMOVED_SETTINGS: set[str] = set()

cat_service_settings = SettingsHolder(
    setting_name=SETTING_NAME,
    defaults=DEFAULTS,
    import_strings=IMPORT_STRINGS,
    removed_settings=REMOVED_SETTINGS,
)

reload_my_settings = reload_settings(SETTING_NAME, cat_service_settings)
setting_changed.connect(reload_my_settings)
