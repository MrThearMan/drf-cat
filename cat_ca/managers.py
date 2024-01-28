from __future__ import annotations

from django.db import models

from cat_ca.querysets import ServiceEntityQuerySet, ServiceEntityTypeQuerySet

__all__ = [
    "ServiceEntityTypeManager",
    "ServiceEntityManager",
]


class ServiceEntityTypeManager(models.Manager.from_queryset(ServiceEntityTypeQuerySet)):
    pass


class ServiceEntityManager(models.Manager.from_queryset(ServiceEntityQuerySet)):
    pass
