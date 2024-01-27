from __future__ import annotations

import json
from hmac import digest

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ed25519

from cat_service.settings import cat_service_settings
from cat_service.utils import get_cat_verification_key

__all__ = [
    "create_cat",
    "create_cat_creation_key",
    "create_cat_header",
    "create_csr",
    "create_client_private_key",
    "hmac",
]


def hmac(*, msg: str, key: str) -> str:
    return digest(
        key=key.encode(),
        msg=msg.encode(),
        digest=cat_service_settings.PSEUDO_RANDOM_FUNCTION,
    ).hex()


def create_cat_creation_key(*, identity: str) -> str:
    return hmac(msg=identity, key=get_cat_verification_key())


def create_cat(*, identity: str, service_name: str, **kwargs: str) -> str:
    creation_key = create_cat_creation_key(identity=identity)
    kwargs["identity"] = identity
    kwargs["service_name"] = service_name
    cat_info = json.dumps(kwargs, sort_keys=True, default=str)
    return hmac(msg=cat_info, key=creation_key)


def create_cat_header(*, identity: str, service_name: str, **kwargs: str) -> str:
    cat = create_cat(identity=identity, service_name=service_name, **kwargs)
    return f"{cat_service_settings.AUTH_SCHEME} {cat}"


def create_client_private_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def create_csr(private_key: ed25519.Ed25519PrivateKey) -> x509.CertificateSigningRequest:
    if cat_service_settings.SERVICE_NAME == "":  # pragma: no cover
        msg = "`CAT_SETTINGS['SERVICE_NAME']` must be set."
        raise ValueError(msg)

    subject: list[x509.NameAttribute] = [x509.NameAttribute(NameOID.COMMON_NAME, cat_service_settings.SERVICE_NAME)]
    if cat_service_settings.SERVICE_ORGANIZATION:  # pragma: no cover
        subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, cat_service_settings.SERVICE_ORGANIZATION))

    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject)).sign(private_key, None)
