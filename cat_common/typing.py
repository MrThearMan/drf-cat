from __future__ import annotations

import sys
from typing import Any, Callable, ClassVar, Iterable, NamedTuple, TypeAlias

if sys.version_info < (3, 11):
    from typing_extensions import Self
else:
    from typing import Self

__all__ = [
    "Any",
    "Callable",
    "ClassVar",
    "HeaderKey",
    "HeaderValue",
    "Iterable",
    "NamedTuple",
    "Self",
    "TypeAlias",
]

HeaderKey: TypeAlias = str
"""Will be in Header-Case."""
HeaderValue: TypeAlias = str
"""Can be anything."""
