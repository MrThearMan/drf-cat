import pytest

from cat_ca.cryptography import create_client_certificate, get_ca_certificate
from cat_common.cryptography import serialize_certificate
from cat_service.cryptography import create_csr


@pytest.fixture()
def client_cert_header() -> str:
    get_ca_certificate()
    cert = create_client_certificate(create_csr())
    return f"Certificate {serialize_certificate(cert)}"
