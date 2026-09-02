import sys
import zipfile
from pathlib import Path

from cryptography import x509
from lxml import etree

import os
import shutil
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes

DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

NAMESPACES = {
    "ds": DSIG_NS
}

EXPECTED_UIDAI_CERT_SHA256 = (
    "E0304B9E61EE3640ECDDAE2DB4B617F2"
    "E2678F57DBC2826C2F86AC5C04F277DF"
)

def verify_uidai_certificate_fingerprint(cert_path: str):
    """
    Ensure the local certificate is the expected trusted UIDAI
    Offline e-KYC signing certificate.
    """

    cert = load_uidai_certificate(cert_path)

    actual = (
        cert.fingerprint(hashes.SHA256())
        .hex()
        .upper()
    )

    if actual != EXPECTED_UIDAI_CERT_SHA256:
        raise ValueError(
            "UIDAI certificate fingerprint mismatch"
        )

    return cert

def load_uidai_certificate(cert_path: str):
    """
    Load UIDAI X.509 certificate.
    Supports both PEM and DER encoded .cer files.
    """

    cert_bytes = Path(cert_path).read_bytes()

    try:
        return x509.load_pem_x509_certificate(cert_bytes)
    except ValueError:
        return x509.load_der_x509_certificate(cert_bytes)


def extract_xml_from_zip(zip_path: str, share_code: str) -> bytes:
    """
    Read Aadhaar Offline e-KYC XML directly from ZIP.

    The XML is kept in memory rather than extracted to disk.
    """

    with zipfile.ZipFile(zip_path, "r") as zf:

        xml_files = [
            info
            for info in zf.infolist()
            if not info.is_dir()
            and info.filename.lower().endswith(".xml")
        ]

        if len(xml_files) == 0:
            raise ValueError("No XML file found inside Aadhaar ZIP")

        if len(xml_files) > 1:
            raise ValueError(
                f"Expected one XML file, found {len(xml_files)}"
            )

        xml_info = xml_files[0]

        # Basic protection against unexpectedly large input
        if xml_info.file_size > 10 * 1024 * 1024:
            raise ValueError("XML file is unexpectedly large")

        try:
            xml_bytes = zf.read(
                xml_info,
                pwd=share_code.encode("utf-8")
            )
        except RuntimeError as exc:
            raise ValueError(
                "Unable to open Aadhaar ZIP. Check Share Code."
            ) from exc

    return xml_bytes


def create_secure_parser():
    """
    XML parser configured to avoid external entity/network processing.
    """

    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        huge_tree=False,
        remove_blank_text=False,
    )


def inspect_signature_algorithm(xml_bytes: bytes):
    """
    Read the algorithms declared by the XML Digital Signature.

    No Aadhaar data is trusted at this stage.
    """

    root = etree.fromstring(
        xml_bytes,
        parser=create_secure_parser()
    )

    signature = root.find("./ds:Signature", NAMESPACES)

    if signature is None:
        raise ValueError("XML Digital Signature not found")

    signature_method = signature.find(
        "./ds:SignedInfo/ds:SignatureMethod",
        NAMESPACES
    )

    digest_method = signature.find(
        "./ds:SignedInfo/ds:Reference/ds:DigestMethod",
        NAMESPACES
    )

    if signature_method is None or digest_method is None:
        raise ValueError(
            "SignatureMethod or DigestMethod missing"
        )

    return (
        signature_method.get("Algorithm"),
        digest_method.get("Algorithm"),
    )

def verify_aadhaar_signature(
    xml_bytes: bytes,
    uidai_cert_path: str,
):
    """
    Verify Aadhaar XML Digital Signature using xmlsec1.

    The UIDAI certificate is independently fingerprint-pinned
    before being used for XML signature verification.
    """

    # ------------------------------------------------
    # 1. Verify trusted UIDAI certificate
    # ------------------------------------------------

    verify_uidai_certificate_fingerprint(
        uidai_cert_path
    )


    # ------------------------------------------------
    # 2. Ensure xmlsec1 exists
    # ------------------------------------------------

    xmlsec_path = shutil.which("xmlsec1")

    if xmlsec_path is None:
        raise RuntimeError(
            "xmlsec1 is not installed"
        )


    # ------------------------------------------------
    # 3. Determine signature algorithms for reporting
    # ------------------------------------------------

    signature_algorithm, digest_algorithm = \
        inspect_signature_algorithm(xml_bytes)


    # ------------------------------------------------
    # 4. Write XML to secure temporary file
    #
    # xmlsec1 works with a file.
    # NamedTemporaryFile uses restrictive permissions
    # on Unix and we delete it immediately afterwards.
    # ------------------------------------------------

    temp_path = None

    try:

        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".xml",
            delete=False
        ) as temp_file:

            temp_file.write(xml_bytes)

            temp_path = temp_file.name


        # ------------------------------------------------
        # 5. Verify XMLDSIG
        #
        # UIDAI's Reference URI in your actual XML is "".
        # Restricting reference URIs to "empty" prevents
        # external/local resource dereferencing.
        # ------------------------------------------------

        command = [
            xmlsec_path,
            "--verify",

            "--pubkey-cert-pem",
            uidai_cert_path,

            "--enabled-reference-uris",
            "empty",

            temp_path,
        ]


        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )


        # xmlsec1 exit code 0 = successful verification
        if result.returncode != 0:

            raise ValueError(
                "Aadhaar XML digital signature verification failed"
            )


        # ------------------------------------------------
        # 6. Parse XML ONLY after cryptographic verification
        # ------------------------------------------------

        verified_root = etree.fromstring(
            xml_bytes,
            parser=create_secure_parser()
        )


        return {
            "signature_valid": True,
            "signature_algorithm":
                signature_algorithm,
            "digest_algorithm":
                digest_algorithm,
            "signed_xml":
                verified_root,
        }


    finally:

        if (
            temp_path is not None
            and os.path.exists(temp_path)
        ):

            os.remove(temp_path)


def mask_reference_id(reference_id: str | None):
    if not reference_id:
        return None

    if len(reference_id) <= 8:
        return "****"

    return "****" + reference_id[-8:]


def parse_verified_aadhaar(signed_root):
    """
    Parse Aadhaar data ONLY AFTER signature verification.
    """

    if etree.QName(signed_root).localname != "OfflinePaperlessKyc":
        raise ValueError(
            "Signed document is not OfflinePaperlessKyc"
        )

    poi = signed_root.find("./UidData/Poi")
    poa = signed_root.find("./UidData/Poa")
    photo = signed_root.find("./UidData/Pht")

    if poi is None:
        raise ValueError("Poi element missing")

    reference_id = (
        signed_root.get("referenceId")
        or signed_root.get("r")
    )

    result = {
        "reference_id": reference_id,

        "name": poi.get("name"),
        "dob": poi.get("dob"),
        "gender": poi.get("gender"),

        # Do not print/hash-log actual values unnecessarily.
        "mobile_hash_present": bool(poi.get("m")),
        "email_hash_present": bool(poi.get("e")),

        "photo_present": bool(
            photo is not None
            and photo.text
            and photo.text.strip()
        ),

        "address": None,
    }

    if poa is not None:
        result["address"] = {
            "care_of": poa.get("careof"),
            "house": poa.get("house"),
            "street": poa.get("street"),
            "locality": poa.get("loc"),
            "vtc": poa.get("vtc"),
            "post_office": poa.get("po"),
            "district": poa.get("dist"),
            "subdistrict": poa.get("subdist"),
            "state": poa.get("state"),
            "country": poa.get("country"),
            "pincode": poa.get("pc"),
        }

    return result


def process_aadhaar(
    zip_path: str,
    share_code: str,
    cert_path: str,
):
    print("1. Reading encrypted Aadhaar ZIP...")

    xml_bytes = extract_xml_from_zip(
        zip_path,
        share_code
    )

    print("   XML extracted successfully")

    print("2. Inspecting digital signature...")

    signature_algorithm, digest_algorithm = \
        inspect_signature_algorithm(xml_bytes)

    print(
        f"   Signature algorithm: "
        f"{signature_algorithm}"
    )

    print(
        f"   Digest algorithm: "
        f"{digest_algorithm}"
    )

    print("3. Verifying UIDAI digital signature...")

    verification = verify_aadhaar_signature(
        xml_bytes,
        cert_path
    )

    print("   Signature verification: VALID")

    print("4. Parsing verified Aadhaar data...")

    kyc = parse_verified_aadhaar(
        verification["signed_xml"]
    )

    # Minimal console output.
    # Avoid dumping complete Aadhaar KYC information.
    print("\n--- Verification Result ---")
    print("Signature valid : YES")
    print(
        "Reference ID    :",
        mask_reference_id(kyc["reference_id"])
    )
    print("Name parsed      :", bool(kyc["name"]))
    print("DOB parsed       :", bool(kyc["dob"]))
    print("Gender parsed    :", bool(kyc["gender"]))
    print("Photo present    :", kyc["photo_present"])
    print(
        "Mobile hash     :",
        kyc["mobile_hash_present"]
    )
    print(
        "Email hash      :",
        kyc["email_hash_present"]
    )

    return kyc


if __name__ == "__main__":

    if len(sys.argv) != 4:
        print(
            "Usage:\n"
            "python verify_aadhaar.py "
            "<aadhaar.zip> "
            "<share_code> "
            "<uidai_certificate.cer>"
        )
        sys.exit(1)

    aadhaar_zip = sys.argv[1]
    share_code = sys.argv[2]
    certificate = sys.argv[3]

    try:
        process_aadhaar(
            aadhaar_zip,
            share_code,
            certificate,
        )

    except Exception as exc:
        print("\nVerification FAILED")
        print(type(exc).__name__ + ":", str(exc))
        sys.exit(2)