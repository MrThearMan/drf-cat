from __future__ import annotations

from typing import TYPE_CHECKING

from cat_common import known_headers
from cat_service.settings import cat_service_settings

if TYPE_CHECKING:
    from cat_common.typing import Iterable


__all__ = [
    "as_human_readable_list",
    "get_required_cat_headers",
    "get_valid_cat_headers",
    "header_case_to_snake_case",
    "snake_case_to_header_case",
    "to_cat_header_name",
]


def to_cat_header_name(name: str) -> str:
    """
    Convert a snake_case string to a Header-Case string with 'CAT' prefixed.

    >>> to_cat_header_name("snake_case")
    'CAT-Snake-Case'
    """
    return f"CAT-{snake_case_to_header_case(name)}"


def from_cat_header_name(name: str) -> str:
    """
    Convert a Header-Case string with 'CAT' prefixed to a snake_case string.

    >>> from_cat_header_name("CAT-Snake-Case")
    'snake_case'
    """
    return header_case_to_snake_case(name[4:])


def snake_case_to_header_case(string: str) -> str:
    """
    Convert a snake_case string to a Header-Case string.

    >>> snake_case_to_header_case("snake_case")
    'Snake-Case'
    """
    return "-".join(value.capitalize() for value in string.split("_"))


def header_case_to_snake_case(string: str) -> str:
    """
    Convert a Header-Case string to a snake_case string.

    >>> header_case_to_snake_case("Header-Case")
    'header_case'
    """
    return "_".join(value.lower() for value in string.split("-"))


def as_human_readable_list(_values: Iterable[str], /, *, last_sep: str = "&") -> str:
    """
    Convert an iterable into a human-readable list.

    >>> as_human_readable_list(["a", "b", "c"])
    "'a', 'b' & 'c'"
    """
    output: str = ""
    addition: str = ""
    more_than_one_item: bool = False
    for i, value in enumerate(_values):
        if i > 1:
            addition = f", {addition}"
        elif i == 1:
            more_than_one_item = True

        output += addition
        addition = f"'{value}'"

    if not more_than_one_item:
        return addition

    output += f" {last_sep} {addition}"
    return output


def get_required_cat_headers() -> set[str]:
    """Required CAT headers in Header-Case with 'CAT' prefixed (e.g., CAT-Service-Name)."""
    return set(cat_service_settings.ADDITIONAL_REQUIRED_CAT_HEADERS) | {
        known_headers.IDENTITY,
        known_headers.SERVICE_NAME,
    }


def get_valid_cat_headers() -> set[str]:
    """Valid CAT headers in Header-Case with 'CAT' prefixed (e.g., CAT-Service-Name)."""
    return set(cat_service_settings.ADDITIONAL_VALID_CAT_HEADERS) | {
        known_headers.IDENTITY,
        known_headers.SERVICE_NAME,
        known_headers.TIMESTAMP,
        known_headers.VALID_UNTIL,
        known_headers.NONCE,
    }
