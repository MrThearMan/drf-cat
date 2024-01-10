import sys
from typing import Any, NamedTuple

if sys.version_info < (3, 11):
    from typing_extensions import Self
else:
    from typing import Self

__all__ = [
    "NamedTuple",
    "Any",
    "Self",
]
