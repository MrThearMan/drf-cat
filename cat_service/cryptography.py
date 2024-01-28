from __future__ import annotations

import json

import httpx
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ed25519

from cat_common.cryptography import deserialize_certificate, hmac, serialize_certificate, serialize_csr
from cat_service.settings import cat_service_settings

__all__ = [
    "create_cat",
    "create_cat_header",
    "create_csr",
    "get_cat_creation_key",
]


def get_cat_verification_key(*, force_refresh: bool = False) -> str:
    """Get the verification key for a given service entity."""
    if not force_refresh and cat_service_settings.VERIFICATION_KEY != "":
        return cat_service_settings.VERIFICATION_KEY

    url = cat_service_settings.VERIFICATION_KEY_URL
    data = {
        "type": cat_service_settings.SERVICE_TYPE,
        "name": cat_service_settings.SERVICE_NAME,
    }

    certificate = cat_service_settings.SERVICE_CERTIFICATE
    if certificate is None:
        certificate = get_certificate()

    headers = {"Authorization": f"Certificate {serialize_certificate(certificate)}"}
    response = httpx.post(url, json=data, follow_redirects=True, headers=headers)
    response.raise_for_status()

    response_data = response.json()
    cat_service_settings.VERIFICATION_KEY = response_data["verification_key"]
    return cat_service_settings.VERIFICATION_KEY


def get_cat_creation_key(*, identity: str) -> str:
    verification_key = get_cat_verification_key()
    return hmac(msg=identity, key=verification_key)


def create_cat(*, identity: str, service_name: str, **kwargs: str) -> str:
    creation_key = get_cat_creation_key(identity=identity)
    kwargs["identity"] = identity
    kwargs["service_name"] = service_name
    cat_info = json.dumps(kwargs, sort_keys=True, default=str)
    return hmac(msg=cat_info, key=creation_key)


def create_cat_header(*, identity: str, service_name: str, **kwargs: str) -> str:
    cat = create_cat(identity=identity, service_name=service_name, **kwargs)
    return f"{cat_service_settings.AUTH_SCHEME} {cat}"


def get_certificate(*, force_refresh: bool = False) -> x509.Certificate:
    if not force_refresh and cat_service_settings.SERVICE_CERTIFICATE is not None:  # pragma: no cover
        # TODO: Validate that certificate is still valid.
        return cat_service_settings.SERVICE_CERTIFICATE

    csr = create_csr()
    url = cat_service_settings.CERTIFICATE_URL
    data = {"csr": serialize_csr(csr)}

    response = httpx.post(url, json=data, follow_redirects=True)
    response.raise_for_status()

    response_data = response.json()
    # TODO: Validate that the certificate was signed by what we expect.
    cat_service_settings.SERVICE_CERTIFICATE = deserialize_certificate(response_data["certificate"])
    return cat_service_settings.SERVICE_CERTIFICATE


def create_csr() -> x509.CertificateSigningRequest:
    subject: list[x509.NameAttribute] = [x509.NameAttribute(NameOID.COMMON_NAME, cat_service_settings.SERVICE_NAME)]
    if cat_service_settings.SERVICE_ORGANIZATION:  # pragma: no cover
        subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, cat_service_settings.SERVICE_ORGANIZATION))

    # Generate a new private key if one does not exist
    if cat_service_settings.SERVICE_PRIVATE_KEY is None:
        cat_service_settings.SERVICE_PRIVATE_KEY = ed25519.Ed25519PrivateKey.generate()

    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(subject))
        .sign(cat_service_settings.SERVICE_PRIVATE_KEY, None)
    )
