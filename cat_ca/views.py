from __future__ import annotations

from typing import TYPE_CHECKING

from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from cat_ca.cryptography import create_cat_creation_key, create_cat_verification_key
from cat_ca.exceptions import ServiceEntityNotFound, ServiceEntityTypeNotFound
from cat_ca.models import ServiceEntity, ServiceEntityType
from cat_ca.serializers import (
    CATCreationKeyInputSerializer,
    CATCreationKeyOutputSerializer,
    CATVerificationKeyInputSerializer,
    CATVerificationKeyOutputSerializer,
)
from cat_common.settings import cat_common_settings

if TYPE_CHECKING:
    from rest_framework.request import Request

    from cat_ca.typing import Any


__all__ = [
    "CATVerificationKeyView",
    "CATCreationKeyView",
]


class PublicCertificateView(APIView):
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        # TODO: implement
        data = {
            "certificate": "",
        }
        return Response(data=data, status=200)


class SignCertificateView(APIView):
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        pass


class CATVerificationKeyView(APIView):
    # TODO: authentication check here

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
