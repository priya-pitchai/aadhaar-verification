import sys
import zipfile
import base64
import hashlib
from copy import deepcopy

from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
NS = {"ds": DSIG_NS}


def load_certificate(path):
    data = open(path, "rb").read()

    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


def secure_parser():
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        remove_blank_text=False,
        huge_tree=False
    )


def remove_signature_preserve_tail(signature):
    """
    Remove <Signature> while preserving whitespace after it.
    This matters for XML canonicalization.
    """
    parent = signature.getparent()
    tail = signature.tail

    previous = signature.getprevious()

    if tail:
        if previous is not None:
            previous.tail = (previous.tail or "") + tail
        else:
            parent.text = (parent.text or "") + tail

    parent.remove(signature)


zip_path = sys.argv[1]
share_code = sys.argv[2]
cert_path = sys.argv[3]


# ---------------------------------------------------
# 1. Extract Aadhaar XML in memory
# ---------------------------------------------------

with zipfile.ZipFile(zip_path, "r") as zf:

    xml_files = [
        f for f in zf.infolist()
        if not f.is_dir()
        and f.filename.lower().endswith(".xml")
    ]

    if len(xml_files) != 1:
        raise ValueError(
            f"Expected exactly one XML file; found {len(xml_files)}"
        )

    xml_bytes = zf.read(
        xml_files[0],
        pwd=share_code.encode("utf-8")
    )


# ---------------------------------------------------
# 2. Parse XML
# ---------------------------------------------------

root = etree.fromstring(
    xml_bytes,
    parser=secure_parser()
)

signature = root.find("./ds:Signature", NS)

if signature is None:
    raise ValueError("Signature element not found")


signed_info = signature.find("./ds:SignedInfo", NS)
signature_value_element = signature.find(
    "./ds:SignatureValue",
    NS
)

digest_value_element = signature.find(
    "./ds:SignedInfo/ds:Reference/ds:DigestValue",
    NS
)

canonicalization_method = signature.find(
    "./ds:SignedInfo/ds:CanonicalizationMethod",
    NS
)

signature_method = signature.find(
    "./ds:SignedInfo/ds:SignatureMethod",
    NS
)

digest_method = signature.find(
    "./ds:SignedInfo/ds:Reference/ds:DigestMethod",
    NS
)

reference = signature.find(
    "./ds:SignedInfo/ds:Reference",
    NS
)


print("\n--- XML Signature Metadata ---")

print(
    "Canonicalization :",
    canonicalization_method.get("Algorithm")
)

print(
    "Signature method :",
    signature_method.get("Algorithm")
)

print(
    "Digest method    :",
    digest_method.get("Algorithm")
)

print(
    "Reference URI    :",
    repr(reference.get("URI"))
)


# ---------------------------------------------------
# 3. Test document DigestValue
# ---------------------------------------------------

document_copy = deepcopy(root)

signature_copy = document_copy.find(
    "./ds:Signature",
    NS
)

remove_signature_preserve_tail(signature_copy)


# UIDAI XML declares Canonical XML 1.0
canonical_document = etree.tostring(
    document_copy,
    method="c14n",
    exclusive=False,
    with_comments=False
)


calculated_digest = hashlib.sha256(
    canonical_document
).digest()

expected_digest = base64.b64decode(
    "".join(digest_value_element.text.split())
)


print("\n--- Reference Digest Test ---")

print(
    "SHA-256 document digest matches :",
    calculated_digest == expected_digest
)


# ---------------------------------------------------
# 4. Canonicalize SignedInfo
# ---------------------------------------------------

canonical_signed_info = etree.tostring(
    signed_info,
    method="c14n",
    exclusive=False,
    with_comments=False
)


signature_value = base64.b64decode(
    "".join(signature_value_element.text.split())
)


# ---------------------------------------------------
# 5. Load trusted UIDAI public key
# ---------------------------------------------------

certificate = load_certificate(cert_path)
public_key = certificate.public_key()


def verify_with_hash(hash_algorithm):

    try:
        public_key.verify(
            signature_value,
            canonical_signed_info,
            padding.PKCS1v15(),
            hash_algorithm
        )

        return True

    except InvalidSignature:
        return False


# ---------------------------------------------------
# 6. Test both possible algorithms
# ---------------------------------------------------

sha1_result = verify_with_hash(
    hashes.SHA1()
)

sha256_result = verify_with_hash(
    hashes.SHA256()
)


print("\n--- RSA Signature Test ---")

print(
    "Signature verifies using RSA-SHA1   :",
    sha1_result
)

print(
    "Signature verifies using RSA-SHA256 :",
    sha256_result
)


print("\n--- Diagnosis Complete ---")