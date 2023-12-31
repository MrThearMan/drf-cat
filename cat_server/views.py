from __future__ import annotations

from typing import TYPE_CHECKING

from rest_framework.exceptions import ParseError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from cat_server.cryptography import hmac
from cat_server.exceptions import ServiceEntityNotFound, ServiceEntityTypeNotFound
from cat_server.models import ServiceEntity, ServiceEntityType
from cat_server.serializers import (
    CATCreationKeyInputSerializer,
    CATCreationKeyOutputSerializer,
    CATVerificationKeyInputSerializer,
    CATVerificationKeyOutputSerializer,
)
from cat_server.settings import cat_server_settings

if TYPE_CHECKING:
    from rest_framework.request import Request

    from cat_server.typing import Any


__all__ = [
    "CATVerificationKeyView",
    "CATCreationKeyView",
]


class CATVerificationKeyView(APIView):
    # TODO: authentication check here

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        request_input = CATVerificationKeyInputSerializer(data=request.data)
        request_input.is_valid(raise_exception=True)
        input_data = request_input.validated_data

        if not ServiceEntity.objects.filter(type__name=input_data["type"], name=input_data["name"]).exists():
            raise ServiceEntityNotFound(entity_type=input_data["type"], name=input_data["name"])

        verification_key = hmac(msg=input_data["type"])
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
        identity = self.get_identity(request)
        if identity is None:  # pragma: no cover
            msg = "User identity not found."
            raise ParseError(msg)

        if not ServiceEntityType.objects.filter(name=input_data["service"]).exists():
            raise ServiceEntityTypeNotFound(name=input_data["service"])

        verification_key = hmac(msg=input_data["service"])
        creation_key = hmac(msg=identity, key=verification_key)
        response_output = CATCreationKeyOutputSerializer(data={"creation_key": creation_key})
        response_output.is_valid(raise_exception=True)

        return Response(data=response_output.validated_data, status=200)

    def get_identity(self, request: Request) -> str | None:
        identity = getattr(request.user, cat_server_settings.IDENTITY_KEY, None)
        return str(identity) if identity is not None else None
