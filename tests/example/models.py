from uuid import uuid4

from django.contrib.auth.models import AbstractUser
from django.db import models

__all__ = [
    "User",
]


class User(AbstractUser):
    uuid = models.UUIDField(primary_key=True, unique=True, default=uuid4, editable=False)
