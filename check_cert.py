import sys
import zipfile
import base64

from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes


DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"


def load_cert(path):
    data = open(path, "rb").read()

    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        return x509.load_pem_x509_certificate(data)


def fingerprint(cert):
    return cert.fingerprint(
        hashes.SHA256()
    ).hex(":").upper()


zip_path = sys.argv[1]
share_code = sys.argv[2]
cert_path = sys.argv[3]


# Read XML without writing it to disk
with zipfile.ZipFile(zip_path, "r") as zf:

    xml_files = [
        x for x in zf.infolist()
        if x.filename.lower().endswith(".xml")
    ]

    xml_bytes = zf.read(
        xml_files[0],
        pwd=share_code.encode()
    )


parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True
)

root = etree.fromstring(
    xml_bytes,
    parser=parser
)


external_cert = load_cert(cert_path)

print("\nExternal UIDAI certificate")
print("--------------------------")
print("Subject     :", external_cert.subject.rfc4514_string())
print("Issuer      :", external_cert.issuer.rfc4514_string())
print("Fingerprint :", fingerprint(external_cert))


embedded_element = root.find(
    ".//{%s}X509Certificate" % DSIG_NS
)


if embedded_element is None or not embedded_element.text:

    print("\nEmbedded XML certificate")
    print("------------------------")
    print("No X509 certificate embedded in XML")

else:

    cert_text = "".join(
        embedded_element.text.split()
    )

    embedded_cert = x509.load_der_x509_certificate(
        base64.b64decode(cert_text)
    )

    print("\nEmbedded XML certificate")
    print("------------------------")
    print(
        "Subject     :",
        embedded_cert.subject.rfc4514_string()
    )

    print(
        "Issuer      :",
        embedded_cert.issuer.rfc4514_string()
    )

    print(
        "Fingerprint :",
        fingerprint(embedded_cert)
    )


    external_key = external_cert.public_key()
    embedded_key = embedded_cert.public_key()

    same_key = (
        external_key.public_numbers()
        ==
        embedded_key.public_numbers()
    )

    print("\nPublic keys match :", same_key)