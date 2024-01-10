from django.utils.translation import gettext_lazy as __
from rest_framework.exceptions import NotFound

__all__ = [
    "ServiceEntityNotFound",
    "ServiceEntityTypeNotFound",
]


class ServiceEntityNotFound(NotFound):
    default_detail = __("Service entity of type '%(entity_type)s' with name '%(name)s' not found.")
    default_code = "service_entity_not_found"

    def __init__(self, entity_type: str, name: str) -> None:
        detail = self.default_detail % {"entity_type": entity_type, "name": name}
        super().__init__(detail)


class ServiceEntityTypeNotFound(NotFound):
    default_detail = __("Service entity type '%(name)s' not found.")
    default_code = "service_entity_type_not_found"

    def __init__(self, name: str) -> None:
        detail = self.default_detail % {"name": name}
        super().__init__(detail)
