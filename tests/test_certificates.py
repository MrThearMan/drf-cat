from cryptography import x509

from cat_ca.cryptography import create_ca_certificate, create_ca_private_key, create_client_certificate
from cat_service.cryptography import create_client_private_key, create_csr


def get_name(name: x509.Name) -> str:
    return list(name.rdns[0])[0].value


def test_certificate_signing(settings):
    settings.CAT_SETTINGS |= {
        "CA_NAME": "ca",
        "SERVICE_NAME": "client",
    }

    # CA generates a private key
    ca_private_key = create_ca_private_key()
    # CA generates a certificate based on tha private key
    ca_cert = create_ca_certificate(ca_private_key)

    # --> Client requests the CA's certificate

    # Client generates a private key
    client_private_key = create_client_private_key()
    # Client generates a CSR based on the private key
    csr = create_csr(client_private_key)

    # --> Client sends the CSR to the CA

    # Create the certificate for client and sign it with CA private key
    client_cert = create_client_certificate(ca_private_key, ca_cert, csr)

    # --> CA sends the certificate to the client

    # Client now has a certificate signed by the CA
    assert get_name(client_cert.issuer) == "ca"
    assert get_name(client_cert.subject) == "client"

    # --> Send Both certs to server

    # Validate that the certificate is valid
    client_cert.verify_directly_issued_by(ca_cert)  # Cert was issued by this CA
    assert ca_cert.signature == ca_cert.signature  # Cert was signed by this CA
