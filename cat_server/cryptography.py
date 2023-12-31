from hmac import digest

from cat_server.settings import cat_server_settings

__all__ = [
    "hmac",
]


def hmac(*, msg: str, key: str | None = None) -> str:
    if key is None:
        key = cat_server_settings.CAT_ROOT_KEY

    return digest(
        key=key.encode(),
        msg=msg.encode(),
        digest=cat_server_settings.PSEUDO_RANDOM_FUNCTION,
    ).hex()
