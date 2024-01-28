from cryptography import x509
from django.test.client import Client
from rest_framework.reverse import reverse

from cat_ca.cryptography import create_client_certificate, get_ca_certificate
from cat_ca.validation import validate_client_certificate
from cat_common.cryptography import deserialize_certificate, deserialize_csr, serialize_certificate, serialize_csr
from cat_service.cryptography import create_csr


def get_name(name: x509.Name) -> str:
    return name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value


def test_certificate_signing_workflow(settings):
    settings.CAT_SETTINGS = {
        "CA_NAME": "ca",
        "SERVICE_NAME": "client",
    }

    # CA generates a certificate for itself
    get_ca_certificate()

    # Client generates a CSR
    csr = create_csr()

    # Client sends the CSR to the CA
    serialized_csr = serialize_csr(csr)
    csr = deserialize_csr(serialized_csr)

    # CA validates the CSR
    assert csr.is_signature_valid
    # Create the certificate for client and sign it with the CAs private key
    client_cert = create_client_certificate(csr)

    # CA sends the certificate to the client
    serialized_cert = serialize_certificate(client_cert)
    client_cert = deserialize_certificate(serialized_cert)

    # Client now has a certificate signed by the CA
    assert get_name(client_cert.issuer) == "ca"
    assert get_name(client_cert.subject) == "client"

    # Client can now use the certificate to authenticate with the cat service

    # Validate that the client certificate is valid
    validate_client_certificate(client_cert)


def test_certificate_signing_request(settings, client: Client):
    settings.CAT_SETTINGS = {
        "CA_NAME": "ca",
        "SERVICE_NAME": "client",
    }

    # Get CA certificate
    certificate_url = reverse("cat_ca:cat_certificate")
    response = client.get(certificate_url)
    response_data_1 = response.json()
    assert len(response_data_1) == 1
    assert "certificate" in response_data_1

    ca_cert = deserialize_certificate(response_data_1["certificate"])

    assert get_name(ca_cert.issuer) == "ca"
    assert get_name(ca_cert.subject) == "ca"

    # Get client certificate with a CSR
    csr = create_csr()
    data = {"csr": serialize_csr(csr)}
    response = client.post(certificate_url, data=data)
    response_data_2 = response.json()
    assert len(response_data_2) == 1
    assert "certificate" in response_data_2

    client_cert = deserialize_certificate(response_data_2["certificate"])

    assert get_name(client_cert.issuer) == "ca"
    assert get_name(client_cert.subject) == "client"

    # Validate that the client certificate is valid
    validate_client_certificate(client_cert)
