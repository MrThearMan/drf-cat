from dataclasses import dataclass
from typing import NamedTuple

__all__ = [
    "AuthInfo",
    "NamedTuple",
]


@dataclass
class AuthInfo:
    scheme: str
    token: str
    identity_key: str
    identity_value: str
