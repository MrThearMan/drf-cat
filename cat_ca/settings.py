import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from django.core.exceptions import ImproperlyConfigured
from django.test.signals import setting_changed
from settings_holder import SettingsHolder, reload_settings

from cat_ca.typing import NamedTuple

__all__ = [
    "cat_ca_settings",
]


SETTING_NAME: str = "CAT_SETTINGS"


class DefaultSettings(NamedTuple):
    CA_NAME: str = ""
    """Name of the CA."""
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

IMPORT_STRINGS: set[bytes | str] = set()

REMOVED_SETTINGS: set[str] = set()

cat_ca_settings = SettingsHolder(
    setting_name=SETTING_NAME,
    defaults=DEFAULTS,
    import_strings=IMPORT_STRINGS,
    removed_settings=REMOVED_SETTINGS,
)

if cat_ca_settings.CA_NAME == "":  # pragma: no cover
    msg = f"`{SETTING_NAME}['CA_NAME']` must be set."
    raise ImproperlyConfigured(msg)

if cat_ca_settings.CAT_ROOT_KEY == "":  # pragma: no cover
    msg = f"`{SETTING_NAME}['CAT_ROOT_KEY']` must be set."
    raise ImproperlyConfigured(msg)

reload_my_settings = reload_settings(SETTING_NAME, cat_ca_settings)
setting_changed.connect(reload_my_settings)
