from django.db import models
from django.utils.translation import gettext_lazy as __

from cat_server.managers import ServiceEntityManager, ServiceEntityTypeManager

__all__ = [
    "ServiceEntityType",
    "ServiceEntity",
]


class ServiceEntityType(models.Model):
    name: str = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text=__("What is the name of this entity type?"),
    )

    objects = ServiceEntityTypeManager()

    def __str__(self) -> str:
        return self.name

    class Meta:
        base_manager_name = "objects"
        verbose_name = __("Service entity type")
        verbose_name_plural = __("Service entity types")


class ServiceEntity(models.Model):
    type: ServiceEntityType = models.ForeignKey(  # noqa: A003
        ServiceEntityType,
        on_delete=models.PROTECT,
        related_name="service_entities",
        help_text=__("What kind of entity is this?"),
    )
    name: str = models.CharField(
        max_length=255,
        help_text=__("What is the name of this entity?"),
    )

    objects = ServiceEntityManager()

    def __str__(self) -> str:
        return self.identity

    class Meta:
        base_manager_name = "objects"
        verbose_name = __("Service entity")
        verbose_name_plural = __("Service entities")
        ordering = ["type", "name"]
        indexes = [
            models.Index(
                fields=["type", "name"],
                name="service_entity_index",
            ),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["type", "name"],
                name="unique_service_entity",
                violation_error_message=__("An entity with this type and name already exists."),
            ),
        ]

    @property
    def identity(self) -> str:
        return f"{self.type.name}|{self.name}"
