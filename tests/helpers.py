from contextlib import contextmanager
from functools import partial
from unittest.mock import patch

from django.test.client import Client
from httpx import HTTPStatusError
from rest_framework.response import Response


@contextmanager
def use_test_client_for_http(client: Client):
    def post(url_, json, follow_redirects, **kwargs):
        response = client.post(url_, data=json, follow=follow_redirects, **kwargs)
        response.raise_for_status = partial(raise_for_status, response)
        return response

    def raise_for_status(self: Response) -> Response:
        if not (200 <= self.status_code <= 299):
            try:
                error = self.json()["detail"]  # type: ignore[union-attr]
            except Exception:
                error = self.rendered_content

            raise HTTPStatusError(error, request=self._request, response=self)
        return self

    with patch("cat_service.cryptography.httpx.post", side_effect=post) as mock:
        yield mock
