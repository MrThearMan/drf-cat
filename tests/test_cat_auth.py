import re

import pytest
from django.core.exceptions import ImproperlyConfigured
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from cat_server.cryptography import hmac
from cat_service.setup import get_verification_key
from tests.factories import ServiceEntityFactory, UserFactory
from tests.helpers import use_test_client_in_service_setup

pytestmark = [
    pytest.mark.django_db,
]


def test_cat__get_service_verification_key(client: APIClient):
    service_entity = ServiceEntityFactory.create()
    verification_key = hmac(msg=service_entity.type.name)

    data = {"type": service_entity.type.name, "name": service_entity.name}
    url = reverse("cat_server:cat_verification_key")
    response = client.post(url, data=data)

    assert dict(response.data) == {"verification_key": verification_key}


def test_cat__get_service_verification_key__service_entity_missing(client: APIClient):
    data = {"type": "foo", "name": "bar"}
    url = reverse("cat_server:cat_verification_key")
    response = client.post(url, data=data)

    assert dict(response.data) == {"detail": "Service entity of type 'foo' with name 'bar' not found."}


def test_cat__get_creation_key(client: APIClient):
    user = UserFactory.create()
    client.force_login(user=user)

    service_entity = ServiceEntityFactory.create()
    verification_key = hmac(msg=service_entity.type.name)
    creation_key = hmac(msg=str(user.pk), key=verification_key)

    data = {"service": service_entity.type.name}
    url = reverse("cat_server:cat_creation_key")
    response = client.post(url, data=data)

    assert dict(response.data) == {"creation_key": creation_key}


def test_cat__get_creation_key__service_entity_type_missing(client: APIClient):
    user = UserFactory.create()
    client.force_login(user=user)

    data = {"service": "foo"}
    url = reverse("cat_server:cat_creation_key")
    response = client.post(url, data=data)

    assert dict(response.data) == {"detail": "Service entity type 'foo' not found."}


def test_cat__authenticate_user(client: APIClient, settings):
    user = UserFactory.create()
    identity = str(user.pk)
    service_entity = ServiceEntityFactory.create()
    verification_key = hmac(msg=service_entity.type.name)
    creation_key = hmac(msg=identity, key=verification_key)

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_server:cat_verification_key"),
    }

    with use_test_client_in_service_setup(client):
        get_verification_key()

    url = reverse("example")
    response = client.get(url, HTTP_AUTHORIZATION=f"CAT {creation_key}, pk={identity}")

    assert dict(response.data) == {"foo": "bar"}


def test_cat__authenticate_user__missing_service_type(settings):
    service_entity = ServiceEntityFactory.create()

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_server:cat_verification_key"),
    }

    msg = "`CAT_SETTINGS['SERVICE_TYPE']` must be set."
    with pytest.raises(ImproperlyConfigured, match=re.escape(msg)):
        get_verification_key()


def test_cat__authenticate_user__missing_service_name(settings):
    service_entity = ServiceEntityFactory.create()

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_TYPE": service_entity.type.name,
        "VERIFICATION_KEY_URL": reverse("cat_server:cat_verification_key"),
    }

    msg = "`CAT_SETTINGS['SERVICE_NAME']` must be set."
    with pytest.raises(ImproperlyConfigured, match=re.escape(msg)):
        get_verification_key()


def test_cat__authenticate_user__missing_verification_key_url(settings):
    service_entity = ServiceEntityFactory.create()

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
    }

    msg = "`CAT_SETTINGS['VERIFICATION_KEY_URL']` must be set."
    with pytest.raises(ImproperlyConfigured, match=re.escape(msg)):
        get_verification_key()


def test_cat__authenticate_user__dont_request_new_if_set(client: APIClient, settings):
    service_entity = ServiceEntityFactory.create()

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_server:cat_verification_key"),
    }

    with use_test_client_in_service_setup(client) as client:
        get_verification_key()

    assert client.call_count == 1

    with use_test_client_in_service_setup(client) as client:
        get_verification_key()

    assert client.call_count == 0


def test_cat__authenticate_user__do_request_new_if_forced(client: APIClient, settings):
    service_entity = ServiceEntityFactory.create()

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_server:cat_verification_key"),
    }

    with use_test_client_in_service_setup(client) as client:
        get_verification_key()

    assert client.call_count == 1

    with use_test_client_in_service_setup(client) as client:
        get_verification_key(force_refresh=True)

    assert client.call_count == 1


@pytest.mark.parametrize(
    ("header", "error"),
    (
        (
            b"\xd3\x82\xe87<\xa4\x95\xd2\xe6Cu\xd3\xc8\xa0\xed\xfe",
            "Invalid token header. Token string should not contain invalid characters.",
        ),
        (
            "",
            "Invalid token header. Must be of form: 'CAT <token>, pk=<identity_value>'.",
        ),
        (
            "foo",
            "Invalid token header. Must be of form: 'CAT <token>, pk=<identity_value>'.",
        ),
        (
            "foo, bar, baz",
            "Invalid token header. Must be of form: 'CAT <token>, pk=<identity_value>'.",
        ),
        (
            "foo, bar",
            "Invalid auth token. Must be of form: 'CAT <token>'.",
        ),
        (
            "Token foo, bar",
            "Invalid auth scheme: 'TOKEN'. Accepted: 'CAT'.",
        ),
        (
            "CAT foo, bar",
            "Invalid identity. Must be of form: 'pk=<identity_value>'.",
        ),
        (
            "CAT token, foo=bar",
            "Invalid identity key: 'foo'. Accepted: 'pk'.",
        ),
    ),
)
def test_cat__authenticate_user__invalid_header(client: APIClient, settings, header, error):
    service_entity = ServiceEntityFactory.create()

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_server:cat_verification_key"),
    }

    with use_test_client_in_service_setup(client):
        get_verification_key()

    url = reverse("example")
    response = client.get(url, HTTP_AUTHORIZATION=header)

    assert dict(response.data) == {"detail": error}


def test_cat__authenticate_user__invalid_header__no_verification_key(client: APIClient, settings):
    user = UserFactory.create()
    identity = str(user.pk)
    service_entity = ServiceEntityFactory.create()
    verification_key = hmac(msg=service_entity.type.name)
    creation_key = hmac(msg=identity, key=verification_key)

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_server:cat_verification_key"),
    }

    url = reverse("example")
    response = client.get(url, HTTP_AUTHORIZATION=f"CAT {creation_key}, pk={identity}")

    assert dict(response.data) == {"detail": "Service not set up correctly."}


def test_cat__authenticate_user__invalid_token(client: APIClient, settings):
    user = UserFactory.create()
    identity = str(user.pk)
    service_entity = ServiceEntityFactory.create()

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_server:cat_verification_key"),
    }

    with use_test_client_in_service_setup(client):
        get_verification_key()

    url = reverse("example")
    response = client.get(url, HTTP_AUTHORIZATION=f"CAT foo, pk={identity}")

    assert dict(response.data) == {"detail": "Invalid token."}
