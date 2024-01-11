import httpx
from django.core.exceptions import ImproperlyConfigured

from cat_service.settings import cat_service_settings


def get_verification_key(*, force_refresh: bool = False) -> None:
    """Get the verification key for a given service entity."""
    if not force_refresh and cat_service_settings.VERIFICATION_KEY != "":
        return

    if cat_service_settings.SERVICE_TYPE == "":
        msg = f"`{cat_service_settings.setting_name}['SERVICE_TYPE']` must be set."
        raise ImproperlyConfigured(msg)

    if cat_service_settings.SERVICE_NAME == "":
        msg = f"`{cat_service_settings.setting_name}['SERVICE_NAME']` must be set."
        raise ImproperlyConfigured(msg)

    if cat_service_settings.VERIFICATION_KEY_URL == "":
        msg = f"`{cat_service_settings.setting_name}['VERIFICATION_KEY_URL']` must be set."
        raise ImproperlyConfigured(msg)

    url = cat_service_settings.VERIFICATION_KEY_URL
    data = {
        "type": cat_service_settings.SERVICE_TYPE,
        "name": cat_service_settings.SERVICE_NAME,
    }

    response = httpx.post(url, json=data, follow_redirects=True)  # TODO: Add authentication
    response.raise_for_status()

    response_data = response.json()
    cat_service_settings.VERIFICATION_KEY = response_data["verification_key"]
