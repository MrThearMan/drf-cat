import datetime
import re

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test.client import Client
from rest_framework.reverse import reverse

from cat_server.cryptography import hmac
from cat_service.cryptography import create_cat_header
from cat_service.setup import get_verification_key
from tests.factories import ServiceEntityFactory, UserFactory
from tests.helpers import use_test_client_in_service_setup

pytestmark = [
    pytest.mark.django_db,
]


def test_cat__get_service_verification_key(client: Client):
    service_entity = ServiceEntityFactory.create()
    verification_key = hmac(msg=service_entity.type.name)

    data = {"type": service_entity.type.name, "name": service_entity.name}
    url = reverse("cat_server:cat_verification_key")
    response = client.post(url, data=data)

    assert response.json() == {"verification_key": verification_key}


def test_cat__get_service_verification_key__service_entity_missing(client: Client):
    data = {"type": "foo", "name": "bar"}
    url = reverse("cat_server:cat_verification_key")
    response = client.post(url, data=data)

    assert response.json() == {"detail": "Service entity of type 'foo' with name 'bar' not found."}


def test_cat__get_creation_key(client: Client):
    user = UserFactory.create()
    client.force_login(user=user)

    service_entity = ServiceEntityFactory.create()
    verification_key = hmac(msg=service_entity.type.name)
    creation_key = hmac(msg=str(user.pk), key=verification_key)

    data = {"service": service_entity.type.name}
    url = reverse("cat_server:cat_creation_key")
    response = client.post(url, data=data)

    assert response.json() == {"creation_key": creation_key}


def test_cat__get_creation_key__service_entity_type_missing(client: Client):
    user = UserFactory.create()
    client.force_login(user=user)

    data = {"service": "foo"}
    url = reverse("cat_server:cat_creation_key")
    response = client.post(url, data=data)

    assert response.json() == {"detail": "Service entity type 'foo' not found."}


def test_cat__authenticate_user(client: Client, settings):
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

    cat = create_cat_header(identity=identity, service_name=service_entity.type.name)

    url = reverse("example")
    response = client.get(
        url,
        HTTP_AUTHORIZATION=cat,
        HTTP_CAT_IDENTITY=identity,
        HTTP_CAT_SERVICE_NAME=service_entity.type.name,
    )

    assert response.json() == {"foo": "bar"}


def test_cat__authenticate_user__cat_headers_in_bytes(client: Client, settings):
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

    cat = create_cat_header(identity=identity, service_name=service_entity.type.name)

    url = reverse("example")
    response = client.get(
        url,
        HTTP_AUTHORIZATION=cat,
        HTTP_CAT_IDENTITY=identity.encode(),
        HTTP_CAT_SERVICE_NAME=service_entity.type.name.encode(),
    )

    assert response.json() == {"foo": "bar"}


def test_cat__authenticate_user__extra_info(client: Client, settings):
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

    timestamp = datetime.datetime(2024, 1, 1).isoformat()
    valid_until = (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat()

    cat = create_cat_header(
        identity=identity,
        service_name=service_entity.type.name,
        timestamp=timestamp,
        valid_until=valid_until,
    )

    url = reverse("example")
    response = client.get(
        url,
        HTTP_AUTHORIZATION=cat,
        HTTP_CAT_IDENTITY=identity,
        HTTP_CAT_SERVICE_NAME=service_entity.type.name,
        HTTP_CAT_TIMESTAMP=timestamp,
        HTTP_CAT_VALID_UNTIL=valid_until,
    )

    assert response.json() == {"foo": "bar"}


def test_cat__authenticate_user__missing_service_type_setting(settings):
    service_entity = ServiceEntityFactory.create()

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_server:cat_verification_key"),
    }

    msg = "`CAT_SETTINGS['SERVICE_TYPE']` must be set."
    with pytest.raises(ImproperlyConfigured, match=re.escape(msg)):
        get_verification_key()


def test_cat__authenticate_user__missing_service_name_setting(settings):
    service_entity = ServiceEntityFactory.create()

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_TYPE": service_entity.type.name,
        "VERIFICATION_KEY_URL": reverse("cat_server:cat_verification_key"),
    }

    msg = "`CAT_SETTINGS['SERVICE_NAME']` must be set."
    with pytest.raises(ImproperlyConfigured, match=re.escape(msg)):
        get_verification_key()


def test_cat__authenticate_user__missing_verification_key_url_setting(settings):
    service_entity = ServiceEntityFactory.create()

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
    }

    msg = "`CAT_SETTINGS['VERIFICATION_KEY_URL']` must be set."
    with pytest.raises(ImproperlyConfigured, match=re.escape(msg)):
        get_verification_key()


def test_cat__authenticate_user__dont_request_new_if_set(client: Client, settings):
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


def test_cat__authenticate_user__do_request_new_if_forced(client: Client, settings):
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
            "Invalid Authorization header. Should not contain non-ASCII characters.",
        ),
        (
            "",
            "Invalid Authorization header. Must be of form: 'CAT <token>'.",
        ),
        (
            "foo",
            "Invalid Authorization header. Must be of form: 'CAT <token>'.",
        ),
        (
            "foo bar baz",
            "Invalid Authorization header. Must be of form: 'CAT <token>'.",
        ),
        (
            "Token foo",
            "Invalid auth scheme: 'TOKEN'. Accepted: 'CAT'.",
        ),
    ),
)
def test_cat__authenticate_user__invalid_header(client: Client, settings, header, error):
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

    assert response.json() == {"detail": error}


def test_cat__authenticate_user__invalid_header__no_verification_key(client: Client, settings):
    user = UserFactory.create()
    identity = str(user.pk)
    service_entity = ServiceEntityFactory.create()

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_server:cat_verification_key"),
    }

    url = reverse("example")
    response = client.get(
        url,
        HTTP_AUTHORIZATION="CAT foo",
        HTTP_CAT_IDENTITY=identity,
        HTTP_CAT_SERVICE_NAME=service_entity.type.name,
    )

    assert response.json() == {"detail": "Service not set up correctly."}


def test_cat__authenticate_user__invalid_cat(client: Client, settings):
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
    response = client.get(
        url,
        HTTP_AUTHORIZATION="CAT foo",
        HTTP_CAT_IDENTITY=identity,
        HTTP_CAT_SERVICE_NAME=service_entity.type.name,
    )

    assert response.json() == {"detail": "Invalid CAT."}


def test_cat__authenticate_user__invalid_service_name(client: Client, settings):
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
    response = client.get(
        url,
        HTTP_AUTHORIZATION="CAT foo",
        HTTP_CAT_IDENTITY=identity,
        HTTP_CAT_SERVICE_NAME="foo",
    )

    assert response.json() == {"detail": "Request not for this service."}


def test_cat__authenticate_user__missing_service_name(client: Client, settings):
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
    response = client.get(
        url,
        HTTP_AUTHORIZATION="CAT foo",
        HTTP_CAT_IDENTITY=identity,
    )

    assert response.json() == {"detail": "Missing 'CAT-Service-Name' header."}


def test_cat__authenticate_user__invalid_identity(client: Client, settings):
    user = UserFactory.create()
    identity = str(user.pk)
    service_entity = ServiceEntityFactory.create()

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_server:cat_verification_key"),
        "IDENTITY_CONVERTER": int,
    }

    with use_test_client_in_service_setup(client):
        get_verification_key()

    url = reverse("example")
    response = client.get(
        url,
        HTTP_AUTHORIZATION="CAT foo",
        HTTP_CAT_IDENTITY=identity,
        HTTP_CAT_SERVICE_NAME=service_entity.type.name,
    )

    assert response.json() == {"detail": f"Invalid identity value: '{identity}'. Could not convert to required type."}


def test_cat__authenticate_user__missing_identity(client: Client, settings):
    service_entity = ServiceEntityFactory.create()

    settings.CAT_SETTINGS = {
        "CAT_ROOT_KEY": "foo",
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_server:cat_verification_key"),
        "IDENTITY_CONVERTER": int,
    }

    with use_test_client_in_service_setup(client):
        get_verification_key()

    url = reverse("example")
    response = client.get(
        url,
        HTTP_AUTHORIZATION="CAT foo",
    )

    assert response.json() == {"detail": "Missing 'CAT-Identity' header."}


def test_cat__authenticate_user__invalid_timestamp(client: Client, settings):
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
    response = client.get(
        url,
        HTTP_AUTHORIZATION="CAT foo",
        HTTP_CAT_IDENTITY=identity,
        HTTP_CAT_SERVICE_NAME=service_entity.type.name,
        HTTP_CAT_TIMESTAMP="foo",
    )

    assert response.json() == {"detail": "Invalid 'CAT-Timestamp' header. Must be in ISO 8601 format."}


def test_cat__authenticate_user__invalid_valid_until(client: Client, settings):
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
    response = client.get(
        url,
        HTTP_AUTHORIZATION="CAT foo",
        HTTP_CAT_IDENTITY=identity,
        HTTP_CAT_SERVICE_NAME=service_entity.type.name,
        HTTP_CAT_VALID_UNTIL="foo",
    )

    assert response.json() == {"detail": "Invalid 'CAT-Valid-Until' header. Must be in ISO 8601 format."}


def test_cat__authenticate_user__expired_valid_until(client: Client, settings):
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
    response = client.get(
        url,
        HTTP_AUTHORIZATION="CAT foo",
        HTTP_CAT_IDENTITY=identity,
        HTTP_CAT_SERVICE_NAME=service_entity.type.name,
        HTTP_CAT_VALID_UNTIL=datetime.datetime(2024, 1, 1).isoformat(),
    )

    assert response.json() == {"detail": "'CAT-Valid-Until' header indicates that the request is no longer valid."}


def test_cat__authenticate_user__invalid_cat_header_chars(client: Client, settings):
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

    cat = create_cat_header(identity=identity, service_name=service_entity.type.name)

    url = reverse("example")
    response = client.get(
        url,
        HTTP_AUTHORIZATION=cat,
        HTTP_CAT_IDENTITY=b"\xd3\x82\xe87<\xa4\x95\xd2\xe6Cu\xd3\xc8\xa0\xed\xfe",
    )

    assert response.json() == {"detail": "Invalid CAT header 'identity'. Should not contain non-ASCII characters."}


def test_cat__authenticate_user__unrecognized_cat_header(client: Client, settings):
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

    cat = create_cat_header(identity=identity, service_name=service_entity.type.name)

    url = reverse("example")
    response = client.get(
        url,
        HTTP_AUTHORIZATION=cat,
        HTTP_CAT_FOOD="foo",
    )

    assert response.json() == {"detail": "Unrecognized CAT header 'CAT-Food'."}
