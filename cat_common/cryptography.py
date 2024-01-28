from __future__ import annotations

import base64
from hmac import digest

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from cat_common.settings import cat_common_settings

__all__ = [
    "deserialize_certificate",
    "deserialize_csr",
    "serialize_certificate",
    "serialize_csr",
]


def hmac(*, msg: str, key: str) -> str:
    return digest(
        key=key.encode(),
        msg=msg.encode(),
        digest=cat_common_settings.PSEUDO_RANDOM_FUNCTION,
    ).hex()


def serialize_certificate(certificate: x509.Certificate) -> str:
    return base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode()


def deserialize_certificate(certificate: str) -> x509.Certificate:
    return x509.load_der_x509_certificate(base64.b64decode(certificate))


def serialize_csr(csr: x509.CertificateSigningRequest) -> str:
    return base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode()


def deserialize_csr(csr: str) -> x509.CertificateSigningRequest:
    return x509.load_der_x509_csr(base64.b64decode(csr))
