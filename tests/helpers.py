from contextlib import contextmanager
from unittest.mock import patch

from django.test.client import Client


@contextmanager
def use_test_client_in_service_setup(client: Client):
    def post(url_, json, follow_redirects, **kwargs):
        response = client.post(url_, data=json, follow=follow_redirects, **kwargs)
        response.raise_for_status = lambda: None
        return response

    with patch("cat_service.setup.httpx.post", side_effect=post) as mock:
        yield mock
