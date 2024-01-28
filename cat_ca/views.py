from __future__ import annotations

from typing import TYPE_CHECKING

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from cat_ca.authentication import CertificatePermission
from cat_ca.cryptography import (
    create_cat_creation_key,
    create_cat_verification_key,
    create_client_certificate,
    get_ca_certificate,
)
from cat_ca.exceptions import ServiceEntityNotFound, ServiceEntityTypeNotFound
from cat_ca.models import ServiceEntity, ServiceEntityType
from cat_ca.serializers import (
    CATCreationKeyInputSerializer,
    CATCreationKeyOutputSerializer,
    CATVerificationKeyInputSerializer,
    CATVerificationKeyOutputSerializer,
    CSRInputSerializer,
    CSROutputSerializer,
)
from cat_common.cryptography import serialize_certificate
from cat_common.settings import cat_common_settings

if TYPE_CHECKING:
    from rest_framework.request import Request

    from cat_common.typing import Any


__all__ = [
    "CATVerificationKeyView",
    "CATCreationKeyView",
]


class CertificateView(APIView):
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Get the public certificate of the CA."""
        # TODO: This creates the certificate if it doesn't exist.
        #  Should the certificate be created on startup instead?
        certificate = get_ca_certificate()
        data = {"certificate": serialize_certificate(certificate)}
        return Response(data=data, status=200)

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Create a new certificate for the client from a certificate signing request."""
        request_input = CSRInputSerializer(data=request.data)
        request_input.is_valid(raise_exception=True)
        input_data = request_input.validated_data

        try:
            certificate = create_client_certificate(input_data["csr"])
        except ValueError as error:
            return Response(data={"detail": error.args[0]}, status=400)

        output_data = {"certificate": serialize_certificate(certificate)}
        response_output = CSROutputSerializer(data=output_data)
        response_output.is_valid(raise_exception=True)

        return Response(data=response_output.validated_data, status=200)


class CATVerificationKeyView(APIView):
    permission_classes = [CertificatePermission]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        request_input = CATVerificationKeyInputSerializer(data=request.data)
        request_input.is_valid(raise_exception=True)
        input_data = request_input.validated_data

        if not ServiceEntity.objects.filter(type__name=input_data["type"], name=input_data["name"]).exists():
            raise ServiceEntityNotFound(entity_type=input_data["type"], name=input_data["name"])

        verification_key = create_cat_verification_key(service=input_data["type"])

        output_data = {"verification_key": verification_key}
        response_output = CATVerificationKeyOutputSerializer(data=output_data)
        response_output.is_valid(raise_exception=True)

        return Response(data=response_output.validated_data, status=200)


class CATCreationKeyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        request_input = CATCreationKeyInputSerializer(data=request.data)
        request_input.is_valid(raise_exception=True)
        input_data = request_input.validated_data

        if not ServiceEntityType.objects.filter(name=input_data["service"]).exists():
            raise ServiceEntityTypeNotFound(name=input_data["service"])

        identify = cat_common_settings.IDENTITY_CONVERTER(request.user.pk)
        creation_key = create_cat_creation_key(identity=identify, service=input_data["service"])

        response_output = CATCreationKeyOutputSerializer(data={"creation_key": creation_key})
        response_output.is_valid(raise_exception=True)

        return Response(data=response_output.validated_data, status=200)
