from hmac import digest

from cat_service.settings import cat_service_settings

__all__ = [
    "hmac",
]


def hmac(*, msg: str, key: str) -> str:
    return digest(
        key=key.encode(),
        msg=msg.encode(),
        digest=cat_service_settings.PSEUDO_RANDOM_FUNCTION,
    ).hex()
