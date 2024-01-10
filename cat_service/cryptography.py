from __future__ import annotations

import json
from hmac import digest

from cat_service.settings import cat_service_settings
from cat_service.utils import get_cat_verification_key

__all__ = [
    "create_cat",
    "create_cat_creation_key",
    "create_cat_header",
    "hmac",
]


def hmac(*, msg: str, key: str) -> str:
    return digest(
        key=key.encode(),
        msg=msg.encode(),
        digest=cat_service_settings.PSEUDO_RANDOM_FUNCTION,
    ).hex()


def create_cat_creation_key(*, identity: str) -> str:
    return hmac(msg=identity, key=get_cat_verification_key())


def create_cat(*, identity: str, service_name: str, **kwargs: str) -> str:
    creation_key = create_cat_creation_key(identity=identity)
    kwargs["identity"] = identity
    kwargs["service_name"] = service_name
    cat_info = json.dumps(kwargs, sort_keys=True, default=str)
    return hmac(msg=cat_info, key=creation_key)


def create_cat_header(*, identity: str, service_name: str, **kwargs: str) -> str:
    cat = create_cat(identity=identity, service_name=service_name, **kwargs)
    return f"{cat_service_settings.AUTH_SCHEME} {cat}"
