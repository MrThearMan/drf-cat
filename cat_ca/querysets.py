from __future__ import annotations

from django.db import models

__all__ = [
    "ServiceEntityTypeQuerySet",
    "ServiceEntityQuerySet",
]


class ServiceEntityTypeQuerySet(models.QuerySet):
    pass


class ServiceEntityQuerySet(models.QuerySet):
    pass
