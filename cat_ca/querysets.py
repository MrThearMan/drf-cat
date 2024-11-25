from __future__ import annotations

from django.db import models

__all__ = [
    "ServiceEntityQuerySet",
    "ServiceEntityTypeQuerySet",
]


class ServiceEntityTypeQuerySet(models.QuerySet):
    pass


class ServiceEntityQuerySet(models.QuerySet):
    pass
