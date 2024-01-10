from typing import Any

import factory
from factory import fuzzy
from factory.django import DjangoModelFactory

from cat_ca.models import ServiceEntity, ServiceEntityType
from tests.example.models import User

__all__ = [
    "ServiceEntityFactory",
    "ServiceEntityTypeFactory",
    "UserFactory",
]


class UserFactory(DjangoModelFactory):
    class Meta:
        model = User

    username = fuzzy.FuzzyText()
    first_name = fuzzy.FuzzyText()
    last_name = fuzzy.FuzzyText()
    email = factory.LazyAttribute(lambda user: f"{user.username}@example.com")

    @classmethod
    def create(cls, **kwargs: Any) -> User:
        return super().create(**kwargs)


class ServiceEntityTypeFactory(DjangoModelFactory):
    class Meta:
        model = ServiceEntityType

    name = fuzzy.FuzzyText()

    @classmethod
    def create(cls, **kwargs: Any) -> ServiceEntityType:
        return super().create(**kwargs)


class ServiceEntityFactory(DjangoModelFactory):
    class Meta:
        model = ServiceEntity

    type = factory.SubFactory(ServiceEntityTypeFactory)
    name = fuzzy.FuzzyText()

    @classmethod
    def create(cls, **kwargs: Any) -> ServiceEntity:
        return super().create(**kwargs)
