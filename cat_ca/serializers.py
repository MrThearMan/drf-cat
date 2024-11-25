from __future__ import annotations

from typing import TYPE_CHECKING

from rest_framework import serializers

from cat_common.cryptography import deserialize_csr

if TYPE_CHECKING:
    from cryptography import x509

    from cat_common.typing import Any


__all__ = [
    "CATCreationKeyInputSerializer",
    "CATCreationKeyOutputSerializer",
    "CATVerificationKeyInputSerializer",
    "CATVerificationKeyOutputSerializer",
    "CSRInputSerializer",
    "CSROutputSerializer",
]


class CATVerificationKeyInputSerializer(serializers.Serializer):
    type = serializers.CharField(max_length=255)
    name = serializers.CharField(max_length=255)


class CATVerificationKeyOutputSerializer(serializers.Serializer):
    verification_key = serializers.CharField()


class CATCreationKeyInputSerializer(serializers.Serializer):
    service = serializers.CharField(max_length=255)


class CATCreationKeyOutputSerializer(serializers.Serializer):
    creation_key = serializers.CharField()


class CSRInputSerializer(serializers.Serializer):
    csr = serializers.CharField()

    def validate_csr(self, value: str) -> x509.CertificateSigningRequest:
        return deserialize_csr(value)

    def validate(self, data: dict[str, Any]) -> dict[str, Any]:
        csr: x509.CertificateSigningRequest = data["csr"]
        if not csr.is_signature_valid:  # pragma: no cover
            msg = "CSR signature is invalid."
            raise ValueError(msg)

        # TODO: Validate `csr.subject` exists.

        return data


class CSROutputSerializer(serializers.Serializer):
    certificate = serializers.CharField()
