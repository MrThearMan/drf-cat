import datetime

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ed25519

from cat_ca.settings import cat_ca_settings
from cat_common.cryptography import hmac

__all__ = [
    "create_client_certificate",
    "create_cat_creation_key",
    "create_cat_verification_key",
    "get_ca_certificate",
]


def create_cat_verification_key(*, service: str) -> str:
    return hmac(msg=service, key=cat_ca_settings.CAT_ROOT_KEY)


def create_cat_creation_key(*, identity: str, service: str) -> str:
    verification_key = create_cat_verification_key(service=service)
    return hmac(msg=identity, key=verification_key)


def get_ca_certificate() -> x509.Certificate:
    if cat_ca_settings.CA_CERTIFICATE is not None:  # pragma: no cover
        return cat_ca_settings.CA_CERTIFICATE

    # Generate a new private key if one does not exist
    if cat_ca_settings.CA_PRIVATE_KEY is None:
        cat_ca_settings.CA_PRIVATE_KEY = ed25519.Ed25519PrivateKey.generate()

    subject: list[x509.NameAttribute] = [x509.NameAttribute(NameOID.COMMON_NAME, cat_ca_settings.CA_NAME)]
    if cat_ca_settings.CA_ORGANIZATION:  # pragma: no cover
        subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, cat_ca_settings.CA_ORGANIZATION))

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    cat_ca_settings.CA_CERTIFICATE = (
        x509.CertificateBuilder()
        .subject_name(x509.Name(subject))
        .issuer_name(x509.Name(subject))
        .public_key(cat_ca_settings.CA_PRIVATE_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - cat_ca_settings.LEEWAY)
        .not_valid_after(now + cat_ca_settings.CA_CERTIFICATE_VALIDITY_PERIOD)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                crl_sign=True,
                key_cert_sign=True,
                key_encipherment=True,
                #
                digital_signature=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(cat_ca_settings.CA_PRIVATE_KEY, None)
    )
    return cat_ca_settings.CA_CERTIFICATE


def create_client_certificate(csr: x509.CertificateSigningRequest) -> x509.Certificate:
    now = datetime.datetime.now(tz=datetime.timezone.utc)

    private_key: ed25519.Ed25519PrivateKey | None = cat_ca_settings.CA_PRIVATE_KEY
    if private_key is None:  # pragma: no cover
        msg = "CA does not have a private key, cannot sign client certificate."
        raise ValueError(msg)

    ca_certificate: x509.Certificate | None = cat_ca_settings.CA_CERTIFICATE
    if ca_certificate is None:  # pragma: no cover
        msg = "CA does not have a certificate, cannot issue a client certificate."
        raise ValueError(msg)

    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_certificate.issuer)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - cat_ca_settings.LEEWAY)
        .not_valid_after(now + cat_ca_settings.CLIENT_CERTIFICATE_VALIDITY_PERIOD)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                #
                crl_sign=False,
                key_cert_sign=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, None)
    )
