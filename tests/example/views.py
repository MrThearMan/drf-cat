from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from cat_service.authentication import CATAuthentication


class ExampleView(APIView):
    authentication_classes = [CATAuthentication]

    def get(self, request: Request) -> Response:
        return Response({"foo": "bar"})
