import sys
import zipfile
import base64
import hashlib

from lxml import etree
from cryptography import x509


DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
NS = {"ds": DSIG_NS}


def load_certificate(path):
    data = open(path, "rb").read()

    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


zip_path = sys.argv[1]
share_code = sys.argv[2]
cert_path = sys.argv[3]


# -------------------------------------------------
# Read Aadhaar XML
# -------------------------------------------------

with zipfile.ZipFile(zip_path, "r") as zf:

    xml_files = [
        f for f in zf.infolist()
        if not f.is_dir()
        and f.filename.lower().endswith(".xml")
    ]

    xml_bytes = zf.read(
        xml_files[0],
        pwd=share_code.encode("utf-8")
    )


parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    remove_blank_text=False
)

root = etree.fromstring(
    xml_bytes,
    parser=parser
)


signature = root.find(
    "./ds:Signature",
    NS
)

signed_info = signature.find(
    "./ds:SignedInfo",
    NS
)

signature_value_element = signature.find(
    "./ds:SignatureValue",
    NS
)


# -------------------------------------------------
# Load UIDAI certificate/public key
# -------------------------------------------------

certificate = load_certificate(cert_path)

public_numbers = (
    certificate
    .public_key()
    .public_numbers()
)

n = public_numbers.n
e = public_numbers.e


signature_bytes = base64.b64decode(
    "".join(
        signature_value_element.text.split()
    )
)


# -------------------------------------------------
# Perform raw RSA public operation
#
# Signature^e mod n
#
# This exposes the PKCS#1 DigestInfo that UIDAI
# originally signed.
# -------------------------------------------------

signature_integer = int.from_bytes(
    signature_bytes,
    byteorder="big"
)

decoded_integer = pow(
    signature_integer,
    e,
    n
)

key_length = (
    n.bit_length() + 7
) // 8

encoded_message = decoded_integer.to_bytes(
    key_length,
    byteorder="big"
)


# -------------------------------------------------
# Validate PKCS#1 v1.5 structure
#
# 00 01 FF FF ... FF 00 DigestInfo
# -------------------------------------------------

if not encoded_message.startswith(b"\x00\x01"):
    raise ValueError(
        "Unexpected RSA PKCS#1 structure"
    )


separator = encoded_message.find(
    b"\x00",
    2
)

if separator == -1:
    raise ValueError(
        "PKCS#1 separator not found"
    )


digest_info = encoded_message[
    separator + 1:
]


# Known ASN.1 DigestInfo prefixes

SHA1_PREFIX = bytes.fromhex(
    "3021300906052b0e03021a05000414"
)

SHA256_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


if digest_info.startswith(SHA1_PREFIX):

    algorithm = "SHA-1"

    signed_digest = digest_info[
        len(SHA1_PREFIX):
    ]

elif digest_info.startswith(SHA256_PREFIX):

    algorithm = "SHA-256"

    signed_digest = digest_info[
        len(SHA256_PREFIX):
    ]

else:

    algorithm = "UNKNOWN"
    signed_digest = digest_info


print("\n--- RSA Signature Internals ---")

print(
    "Digest algorithm encoded in RSA signature :",
    algorithm
)


# -------------------------------------------------
# Our current canonicalization
# -------------------------------------------------

canonical_signed_info = etree.tostring(
    signed_info,
    method="c14n",
    exclusive=False,
    with_comments=False
)


sha1_digest = hashlib.sha1(
    canonical_signed_info
).digest()

sha256_digest = hashlib.sha256(
    canonical_signed_info
).digest()


print("\n--- Canonical SignedInfo Test ---")

print(
    "Recovered digest equals C14N SHA-1   :",
    signed_digest == sha1_digest
)

print(
    "Recovered digest equals C14N SHA-256 :",
    signed_digest == sha256_digest
)


# -------------------------------------------------
# Diagnostic only: raw SignedInfo representation
# -------------------------------------------------

serialized_signed_info = etree.tostring(
    signed_info,
    encoding="UTF-8",
    with_tail=False
)


raw_sha1 = hashlib.sha1(
    serialized_signed_info
).digest()

raw_sha256 = hashlib.sha256(
    serialized_signed_info
).digest()


print("\n--- Non-C14N Diagnostic ---")

print(
    "Recovered digest equals serialized SHA-1   :",
    signed_digest == raw_sha1
)

print(
    "Recovered digest equals serialized SHA-256 :",
    signed_digest == raw_sha256
)


print("\n--- Diagnosis Complete ---")