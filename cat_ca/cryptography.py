import datetime
from hmac import digest

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ed25519

from cat_ca.settings import cat_ca_settings
from cat_ca.validation import validate_csr

__all__ = [
    "hmac",
    "create_ca_private_key",
    "create_ca_certificate",
    "create_client_certificate",
]


def hmac(*, msg: str, key: str | None = None) -> str:
    if key is None:
        key = cat_ca_settings.CAT_ROOT_KEY

    return digest(
        key=key.encode(),
        msg=msg.encode(),
        digest=cat_ca_settings.PSEUDO_RANDOM_FUNCTION,
    ).hex()


def create_ca_private_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def create_ca_certificate(private_key: ed25519.Ed25519PrivateKey) -> x509.Certificate:
    subject: list[x509.NameAttribute] = [x509.NameAttribute(NameOID.COMMON_NAME, cat_ca_settings.CA_NAME)]
    if cat_ca_settings.CA_ORGANIZATION:  # pragma: no cover
        subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, cat_ca_settings.CA_ORGANIZATION))

    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name(subject))
        .issuer_name(x509.Name(subject))
        .public_key(private_key.public_key())
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
        .sign(private_key, None)
    )


def create_client_certificate(
    private_key: ed25519.Ed25519PrivateKey,
    ca_certificate: x509.Certificate,
    csr: x509.CertificateSigningRequest,
) -> x509.Certificate:
    validate_csr(csr)

    now = datetime.datetime.now(datetime.timezone.utc)
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
