import datetime
import re
import secrets

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test.client import Client
from httpx import HTTPStatusError
from rest_framework.reverse import reverse

from cat_ca.cryptography import create_cat_creation_key, create_cat_verification_key, get_ca_certificate
from cat_ca.settings import cat_ca_settings
from cat_common.settings import cat_common_settings
from cat_service.cryptography import create_cat_header, get_cat_verification_key
from tests.factories import ServiceEntityFactory, UserFactory
from tests.helpers import use_test_client_for_http

pytestmark = [
    pytest.mark.django_db,
]


def test_cat__get_service_verification_key(client: Client, client_cert_header):
    service_entity = ServiceEntityFactory.create()
    verification_key = create_cat_verification_key(service=service_entity.type.name)

    data = {"type": service_entity.type.name, "name": service_entity.name}
    url = reverse("cat_ca:cat_verification_key")
    response = client.post(url, data=data, HTTP_AUTHORIZATION=client_cert_header)

    assert response.json() == {"verification_key": verification_key}


def test_cat__get_service_verification_key__service_entity_missing(client: Client, client_cert_header):
    data = {"type": "foo", "name": "bar"}
    url = reverse("cat_ca:cat_verification_key")
    response = client.post(url, data=data, HTTP_AUTHORIZATION=client_cert_header)

    assert response.json() == {"detail": "Service entity of type 'foo' with name 'bar' not found."}


def test_cat__get_creation_key(client: Client):
    user = UserFactory.create()
    client.force_login(user=user)

    service_entity = ServiceEntityFactory.create()
    creation_key = create_cat_creation_key(identity=str(user.pk), service=service_entity.type.name)

    data = {"service": service_entity.type.name}
    url = reverse("cat_ca:cat_creation_key")
    response = client.post(url, data=data)

    assert response.json() == {"creation_key": creation_key}


def test_cat__get_creation_key__service_entity_type_missing(client: Client):
    user = UserFactory.create()
    client.force_login(user=user)

    data = {"service": "foo"}
    url = reverse("cat_ca:cat_creation_key")
    response = client.post(url, data=data)

    assert response.json() == {"detail": "Service entity type 'foo' not found."}


def test_cat__authenticate_user(client: Client, settings):
    user = UserFactory.create()
    identity = str(user.pk)
    service_entity = ServiceEntityFactory.create()
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client):
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
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client):
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
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    timestamp = datetime.datetime(2024, 1, 1).isoformat()
    valid_until = (datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(minutes=5)).isoformat()
    nonce = secrets.token_urlsafe()

    with use_test_client_for_http(client):
        cat = create_cat_header(
            identity=identity,
            service_name=service_entity.type.name,
            timestamp=timestamp,
            valid_until=valid_until,
            nonce=nonce,
        )

    url = reverse("example")
    response = client.get(
        url,
        HTTP_AUTHORIZATION=cat,
        HTTP_CAT_IDENTITY=identity,
        HTTP_CAT_SERVICE_NAME=service_entity.type.name,
        HTTP_CAT_TIMESTAMP=timestamp,
        HTTP_CAT_VALID_UNTIL=valid_until,
        HTTP_CAT_NONCE=nonce,
    )

    assert response.json() == {"foo": "bar"}


def test_cat__authenticate_user__missing_service_type_setting(settings):
    service_entity = ServiceEntityFactory.create()
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    msg = "`CAT_SETTINGS['SERVICE_TYPE']` must be set."
    with pytest.raises(ImproperlyConfigured, match=re.escape(msg)):
        get_cat_verification_key()


def test_cat__authenticate_user__missing_service_name_setting(settings):
    service_entity = ServiceEntityFactory.create()
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    msg = "`CAT_SETTINGS['SERVICE_NAME']` must be set."
    with pytest.raises(ImproperlyConfigured, match=re.escape(msg)):
        get_cat_verification_key()


def test_cat__authenticate_user__missing_verification_key_url_setting(settings):
    service_entity = ServiceEntityFactory.create()
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    msg = "`CAT_SETTINGS['VERIFICATION_KEY_URL']` must be set."
    with pytest.raises(ImproperlyConfigured, match=re.escape(msg)):
        get_cat_verification_key()


def test_cat__authenticate_user__missing_certificate_url(settings):
    service_entity = ServiceEntityFactory.create()
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    msg = "`CAT_SETTINGS['CERTIFICATE_URL']` must be set."
    with pytest.raises(ImproperlyConfigured, match=re.escape(msg)):
        get_cat_verification_key()


def test_cat__authenticate_user__missing_ca_certificate(settings, client: Client):
    service_entity = ServiceEntityFactory.create()
    get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    msg = "CA does not have a certificate, cannot issue a client certificate."
    with pytest.raises(HTTPStatusError, match=re.escape(msg)), use_test_client_for_http(client):
        get_cat_verification_key()


def test_cat__authenticate_user__missing_ca_private_key(settings, client: Client):
    service_entity = ServiceEntityFactory.create()
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
    }

    msg = "CA does not have a private key, cannot sign client certificate."
    with pytest.raises(HTTPStatusError, match=re.escape(msg)), use_test_client_for_http(client):
        get_cat_verification_key()


def test_cat__authenticate_user__dont_request_new_if_set(client: Client, settings):
    service_entity = ServiceEntityFactory.create()
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client) as http:
        get_cat_verification_key()

    # 1 call for the certificate.
    # 1 call for the verification key.
    assert http.call_count == 2

    with use_test_client_for_http(client) as http:
        get_cat_verification_key()

    assert http.call_count == 0


def test_cat__authenticate_user__do_request_new_if_forced(client: Client, settings):
    service_entity = ServiceEntityFactory.create()
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client) as http:
        get_cat_verification_key()

    # 1 call for the certificate.
    # 1 call for the verification key.
    assert http.call_count == 2

    with use_test_client_for_http(client) as http:
        get_cat_verification_key(force_refresh=True)

    # 1 call for the certificate.
    assert http.call_count == 1


@pytest.mark.parametrize(
    ("header", "error"),
    (
        (
            b"\xd3\x82\xe87<\xa4\x95\xd2\xe6Cu\xd3\xc8\xa0\xed\xfe",
            "Invalid Authorization header. Should not contain non-ASCII characters.",
        ),
        (
            "",
            "Missing Authorization header.",
        ),
        (
            "foo",
            "Invalid Authorization header. Must be of form: '<scheme> <token>'.",
        ),
        (
            "foo bar baz",
            "Invalid Authorization header. Must be of form: '<scheme> <token>'.",
        ),
        (
            "Token foo",
            "Invalid auth scheme: 'Token'. Accepted: 'CAT'.",
        ),
    ),
)
def test_cat__authenticate_user__invalid_auth_header(client: Client, settings, header, error):
    service_entity = ServiceEntityFactory.create()
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client):
        get_cat_verification_key()

    url = reverse("example")
    response = client.get(url, HTTP_AUTHORIZATION=header)

    assert response.json() == {"detail": error}


def test_cat__authenticate_user__invalid_cat(client: Client, settings):
    user = UserFactory.create()
    identity = str(user.pk)
    service_entity = ServiceEntityFactory.create()
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client):
        get_cat_verification_key()

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
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client):
        get_cat_verification_key()

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
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client):
        get_cat_verification_key()

    url = reverse("example")
    response = client.get(
        url,
        HTTP_AUTHORIZATION="CAT foo",
        HTTP_CAT_IDENTITY=identity,
    )

    assert response.json() == {"detail": "Missing required headers: 'CAT-Service-Name'."}


def test_cat__authenticate_user__invalid_identity(client: Client, settings):
    user = UserFactory.create()
    identity = str(user.pk)
    service_entity = ServiceEntityFactory.create()
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "IDENTITY_CONVERTER": int,
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client):
        get_cat_verification_key()

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
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "IDENTITY_CONVERTER": int,
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client):
        get_cat_verification_key()

    url = reverse("example")
    response = client.get(
        url,
        HTTP_AUTHORIZATION="CAT foo",
        HTTP_CAT_SERVICE_NAME=service_entity.type.name,
    )

    assert response.json() == {"detail": "Missing required headers: 'CAT-Identity'."}


def test_cat__authenticate_user__invalid_timestamp(client: Client, settings):
    user = UserFactory.create()
    identity = str(user.pk)
    service_entity = ServiceEntityFactory.create()
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client):
        get_cat_verification_key()

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
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client):
        get_cat_verification_key()

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
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client):
        get_cat_verification_key()

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
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client):
        get_cat_verification_key()

    cat = create_cat_header(identity=identity, service_name=service_entity.type.name)

    url = reverse("example")
    response = client.get(
        url,
        HTTP_AUTHORIZATION=cat,
        HTTP_CAT_IDENTITY=b"\xd3\x82\xe87<\xa4\x95\xd2\xe6Cu\xd3\xc8\xa0\xed\xfe",
    )

    assert response.json() == {"detail": "Invalid CAT header 'CAT-Identity'. Should not contain non-ASCII characters."}


def test_cat__authenticate_user__unrecognized_cat_header(client: Client, settings):
    user = UserFactory.create()
    identity = str(user.pk)
    service_entity = ServiceEntityFactory.create()
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client):
        get_cat_verification_key()

    cat = create_cat_header(identity=identity, service_name=service_entity.type.name)

    url = reverse("example")
    response = client.get(
        url,
        HTTP_AUTHORIZATION=cat,
        HTTP_CAT_FOOD="foo",
    )

    assert response.json() == {"detail": "Unrecognized CAT header: 'CAT-Food'."}


def test_cat__authenticate_user__validator_not_found(client: Client, settings):
    user = UserFactory.create()
    identity = str(user.pk)
    service_entity = ServiceEntityFactory.create()
    certificate = get_ca_certificate()

    settings.CAT_SETTINGS = {
        "CA_NAME": cat_common_settings.CA_NAME,
        "CAT_ROOT_KEY": cat_ca_settings.CAT_ROOT_KEY,
        "SERVICE_TYPE": service_entity.type.name,
        "SERVICE_NAME": service_entity.name,
        "VERIFICATION_KEY_URL": reverse("cat_ca:cat_verification_key"),
        "CERTIFICATE_URL": reverse("cat_ca:cat_certificate"),
        "ADDITIONAL_VALID_CAT_HEADERS": ["CAT-Food"],
        "CA_CERTIFICATE": certificate,
        "CA_PRIVATE_KEY": cat_ca_settings.CA_PRIVATE_KEY,
    }

    with use_test_client_for_http(client):
        get_cat_verification_key()

    cat = create_cat_header(identity=identity, service_name=service_entity.type.name)

    url = reverse("example")
    response = client.get(
        url,
        HTTP_AUTHORIZATION=cat,
        HTTP_CAT_FOOD="foo",
    )

    assert response.json() == {"detail": "Missing validation function for header: 'CAT-Food'."}
