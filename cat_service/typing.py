import sys
from typing import Any, Callable, Iterable, NamedTuple, TypeAlias

if sys.version_info < (3, 11):
    from typing_extensions import Self
else:
    from typing import Self

__all__ = [
    "Any",
    "Iterable",
    "NamedTuple",
    "Self",
    "Validator",
    "Callable",
    "TypeAlias",
    "HeaderKey",
    "HeaderValue",
]

Validator: TypeAlias = Callable[[str], Any]

HeaderKey: TypeAlias = str
"""Will be in Header-Case."""
HeaderValue: TypeAlias = str
"""Can be anything."""
