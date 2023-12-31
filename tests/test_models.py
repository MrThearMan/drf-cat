import pytest

from tests.factories import ServiceEntityFactory

pytestmark = [
    pytest.mark.django_db,
]


def test_cat__get_service_verification_key():
    service_entity = ServiceEntityFactory.create(name="foo", type__name="bar")

    assert service_entity.identity == "bar|foo"
    assert str(service_entity) == "bar|foo"
    assert str(service_entity.type) == "bar"
