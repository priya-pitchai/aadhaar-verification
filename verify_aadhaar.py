import sys
import zipfile
from pathlib import Path

import os
import shutil
import subprocess
import tempfile

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from lxml import etree


# ============================================================
# XML Digital Signature namespace
# ============================================================

DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

NAMESPACES = {
    "ds": DSIG_NS
}


# ============================================================
# Certificate paths
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

ROOT_CA_PATH = (
    BASE_DIR
    / "certs"
    / "CCAIndia2022.cer"
)

INTERMEDIATES_PATH = (
    BASE_DIR
    / "certs"
    / "ncode_intermediates.pem"
)

CRL_PATH = (
    BASE_DIR
    / "certs"
    / "ncode_subca_2022.crl"
)

SUBCA_CERT_PATH = (
    BASE_DIR
    / "certs"
    / "ncode_subca_2022.pem"
)

# ============================================================
# Expected UIDAI certificate fingerprint
# ============================================================

EXPECTED_UIDAI_CERT_SHA256 = (
    "E0304B9E61EE3640ECDDAE2DB4B617F2"
    "E2678F57DBC2826C2F86AC5C04F277DF"
)


# ============================================================
# Load UIDAI certificate
# ============================================================

def load_uidai_certificate(cert_path: str):
    """
    Load UIDAI X.509 certificate.

    Supports PEM and DER encoded certificates.
    """

    cert_bytes = Path(cert_path).read_bytes()

    try:
        return x509.load_pem_x509_certificate(
            cert_bytes
        )

    except ValueError:
        return x509.load_der_x509_certificate(
            cert_bytes
        )


# ============================================================
# UIDAI certificate fingerprint pinning
# ============================================================

def verify_uidai_certificate_fingerprint(
    cert_path: str
):
    """
    Ensure the local certificate is the expected
    UIDAI Offline e-KYC signing certificate.
    """

    cert = load_uidai_certificate(
        cert_path
    )

    actual = (
        cert
        .fingerprint(hashes.SHA256())
        .hex()
        .upper()
    )

    if actual != EXPECTED_UIDAI_CERT_SHA256:
        raise ValueError(
            "UIDAI certificate fingerprint mismatch"
        )

    return cert


# ============================================================
# PKI certificate-chain validation
# ============================================================

def verify_certificate_chain(
    uidai_cert_path: str,
    root_ca_path: str,
    intermediates_path: str
) -> bool:
    """
    Verify that the UIDAI signing certificate chains
    to the trusted CCA India 2022 root through the
    nCode CA certificates.

    Expected chain:

        CCA India 2022
              ↓
        nCode Solutions CA 2022
              ↓
        nCode Solutions Sub-CA for DSC 2022
              ↓
        UIDAI signing certificate

    Returns:
        True if certificate chain is valid.

    Raises:
        ValueError if certificate validation fails.
        RuntimeError if OpenSSL is unavailable.
    """

    if not Path(root_ca_path).exists():
        raise ValueError(
            f"Root CA certificate not found: "
            f"{root_ca_path}"
        )

    if not Path(intermediates_path).exists():
        raise ValueError(
            f"Intermediate certificate bundle "
            f"not found: {intermediates_path}"
        )

    if not Path(uidai_cert_path).exists():
        raise ValueError(
            f"UIDAI certificate not found: "
            f"{uidai_cert_path}"
        )

    command = [
        "openssl",
        "verify",
        "-CAfile",
        root_ca_path,
        "-untrusted",
        intermediates_path,
        uidai_cert_path,
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    except FileNotFoundError as exc:

        raise RuntimeError(
            "OpenSSL is not installed "
            "or cannot be found."
        ) from exc

    except subprocess.TimeoutExpired as exc:

        raise RuntimeError(
            "Certificate-chain validation timed out."
        ) from exc

    if result.returncode != 0:

        error_message = (
            result.stderr.strip()
            or result.stdout.strip()
        )

        raise ValueError(
            "UIDAI certificate chain validation "
            f"failed: {error_message}"
        )

    return True

def verify_certificate_revocation(
    uidai_cert_path: str,
    crl_path: str,
    issuer_cert_path: str,
) -> bool:
    """
    Verify that:

    1. The CRL is signed by the expected issuing Sub-CA.
    2. The CRL is currently valid/fresh.
    3. The UIDAI certificate serial number is NOT listed
       in the CRL.

    Expected relationship:

        nCode Sub-CA
             ↓ signs
             CRL

        UIDAI certificate serial
             ↓ checked against
             CRL

    Returns:
        True -> CRL is authentic/current and UIDAI
                certificate is not listed as revoked.

    Raises:
        ValueError   -> CRL validation/revocation check fails.
        RuntimeError -> OpenSSL is unavailable.
    """

    # ------------------------------------------------
    # 1. Ensure required files exist
    # ------------------------------------------------

    if not Path(uidai_cert_path).exists():
        raise ValueError(
            f"UIDAI certificate not found: {uidai_cert_path}"
        )

    if not Path(crl_path).exists():
        raise ValueError(
            f"CRL file not found: {crl_path}"
        )

    if not Path(issuer_cert_path).exists():
        raise ValueError(
            f"CRL issuer certificate not found: "
            f"{issuer_cert_path}"
        )


    # ------------------------------------------------
    # 2. Load UIDAI certificate
    # ------------------------------------------------

    uidai_cert = load_uidai_certificate(
        uidai_cert_path
    )


    # ------------------------------------------------
    # 3. Load CRL
    #    Support both DER and PEM
    # ------------------------------------------------

    crl_bytes = Path(crl_path).read_bytes()

    crl_format = None

    try:
        crl = x509.load_der_x509_crl(
            crl_bytes
        )
        crl_format = "DER"

    except ValueError:

        try:
            crl = x509.load_pem_x509_crl(
                crl_bytes
            )
            crl_format = "PEM"

        except ValueError as exc:
            raise ValueError(
                "Unable to parse CRL as DER or PEM"
            ) from exc


    # ------------------------------------------------
    # 4. Load issuer certificate
    #    This should be:
    #    nCode Solutions Sub-CA for DSC 2022
    # ------------------------------------------------

    issuer_cert = load_uidai_certificate(
        issuer_cert_path
    )


    # ------------------------------------------------
    # 5. Verify issuer relationships
    # ------------------------------------------------

    if uidai_cert.issuer != issuer_cert.subject:
        raise ValueError(
            "UIDAI certificate issuer does not match "
            "the supplied CRL issuer certificate"
        )

    if crl.issuer != issuer_cert.subject:
        raise ValueError(
            "CRL issuer does not match the expected "
            "nCode Sub-CA"
        )


    # ------------------------------------------------
    # 6. Verify CRL digital signature using OpenSSL
    # ------------------------------------------------

    command = [
        "openssl",
        "crl",
        "-inform",
        crl_format,
        "-in",
        crl_path,
        "-CAfile",
        issuer_cert_path,
        "-verify",
        "-noout",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    except FileNotFoundError as exc:
        raise RuntimeError(
            "OpenSSL is not installed "
            "or cannot be found"
        ) from exc

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "CRL signature verification timed out"
        ) from exc


    if result.returncode != 0:

        error_message = (
            result.stderr.strip()
            or result.stdout.strip()
        )

        raise ValueError(
            "CRL signature verification failed: "
            f"{error_message}"
        )


    # ------------------------------------------------
    # 7. Check CRL freshness
    # ------------------------------------------------

    now = datetime.now(timezone.utc)

    # New cryptography versions provide *_utc attributes.
    # Fallback keeps compatibility with older versions.

    if hasattr(crl, "last_update_utc"):
        last_update = crl.last_update_utc
    else:
        last_update = crl.last_update.replace(
            tzinfo=timezone.utc
        )

    if hasattr(crl, "next_update_utc"):
        next_update = crl.next_update_utc
    else:
        next_update = (
            crl.next_update.replace(
                tzinfo=timezone.utc
            )
            if crl.next_update
            else None
        )


    if now < last_update:
        raise ValueError(
            "CRL is not yet valid"
        )


    if next_update is None:
        raise ValueError(
            "CRL does not contain nextUpdate"
        )


    if now > next_update:
        raise ValueError(
            "CRL is stale or expired. "
            "Download the latest CRL."
        )


    # ------------------------------------------------
    # 8. Check UIDAI certificate serial
    #    against revoked certificates
    # ------------------------------------------------

    revoked_certificate = (
        crl.get_revoked_certificate_by_serial_number(
            uidai_cert.serial_number
        )
    )


    if revoked_certificate is not None:

        raise ValueError(
            "UIDAI certificate is REVOKED. "
            f"Serial: {uidai_cert.serial_number:X}"
        )


    # ------------------------------------------------
    # 9. Success
    # ------------------------------------------------

    print("   CRL signature       : VALID")
    print("   CRL freshness       : VALID")
    print(
        "   UIDAI certificate   : NOT REVOKED"
    )

    return True

# ============================================================
# Extract Aadhaar XML from encrypted ZIP
# ============================================================

def extract_xml_from_zip(
    zip_path: str,
    share_code: str
) -> bytes:
    """
    Read Aadhaar Offline e-KYC XML directly
    from encrypted ZIP.

    XML remains in memory and is not permanently
    extracted to disk.
    """

    with zipfile.ZipFile(
        zip_path,
        "r"
    ) as zf:

        xml_files = [
            info
            for info in zf.infolist()
            if not info.is_dir()
            and info.filename
            .lower()
            .endswith(".xml")
        ]

        if len(xml_files) == 0:

            raise wqaValueError(
                "No XML file found inside Aadhaar ZIP"
            )

        if len(xml_files) > 1:

            raise ValueError(
                f"Expected one XML file, "
                f"found {len(xml_files)}"
            )

        xml_info = xml_files[0]

        # Protection against unexpectedly large XML
        if xml_info.file_size > 10 * 1024 * 1024:

            raise ValueError(
                "XML file is unexpectedly large"
            )

        try:

            xml_bytes = zf.read(
                xml_info,
                pwd=share_code.encode("utf-8")
            )

        except RuntimeError as exc:

            raise ValueError(
                "Unable to open Aadhaar ZIP. "
                "Check Share Code."
            ) from exc

    return xml_bytes


# ============================================================
# Secure XML parser
# ============================================================

def create_secure_parser():
    """
    XML parser configured to prevent
    external entity/network processing.
    """

    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        huge_tree=False,
        remove_blank_text=False,
    )


# ============================================================
# Inspect XML signature algorithms
# ============================================================

def inspect_signature_algorithm(
    xml_bytes: bytes
):
    """
    Read the algorithms declared by
    the XML Digital Signature.

    Aadhaar data is not trusted at this stage.
    """

    root = etree.fromstring(
        xml_bytes,
        parser=create_secure_parser()
    )

    signature = root.find(
        "./ds:Signature",
        NAMESPACES
    )

    if signature is None:

        raise ValueError(
            "XML Digital Signature not found"
        )

    signature_method = signature.find(
        "./ds:SignedInfo/ds:SignatureMethod",
        NAMESPACES
    )

    digest_method = signature.find(
        "./ds:SignedInfo/ds:Reference/"
        "ds:DigestMethod",
        NAMESPACES
    )

    if (
        signature_method is None
        or digest_method is None
    ):

        raise ValueError(
            "SignatureMethod or "
            "DigestMethod missing"
        )

    return (
        signature_method.get("Algorithm"),
        digest_method.get("Algorithm"),
    )


# ============================================================
# Verify Aadhaar XML Digital Signature
# ============================================================

def verify_aadhaar_signature(
    xml_bytes: bytes,
    uidai_cert_path: str,
):
    """
    Verify Aadhaar XML Digital Signature
    using xmlsec1.

    The UIDAI certificate is fingerprint-pinned
    before being used for XML verification.
    """

    # ------------------------------------------------
    # 1. Verify expected UIDAI certificate
    # ------------------------------------------------

    verify_uidai_certificate_fingerprint(
        uidai_cert_path
    )


    # ------------------------------------------------
    # 2. Ensure xmlsec1 exists
    # ------------------------------------------------

    xmlsec_path = shutil.which(
        "xmlsec1"
    )

    if xmlsec_path is None:

        raise RuntimeError(
            "xmlsec1 is not installed"
        )


    # ------------------------------------------------
    # 3. Inspect signature algorithms
    # ------------------------------------------------

    (
        signature_algorithm,
        digest_algorithm
    ) = inspect_signature_algorithm(
        xml_bytes
    )


    # ------------------------------------------------
    # 4. Temporary XML file for xmlsec1
    # ------------------------------------------------

    temp_path = None

    try:

        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".xml",
            delete=False
        ) as temp_file:

            temp_file.write(
                xml_bytes
            )

            temp_path = (
                temp_file.name
            )


        # ------------------------------------------------
        # 5. Verify XML Digital Signature
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


        if result.returncode != 0:

            raise ValueError(
                "Aadhaar XML digital signature "
                "verification failed"
            )


        # ------------------------------------------------
        # 6. Parse only AFTER successful verification
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

            os.remove(
                temp_path
            )


# ============================================================
# Mask Aadhaar reference ID
# ============================================================

def mask_reference_id(
    reference_id: str | None
):
    """
    Mask reference ID before console output.
    """

    if not reference_id:
        return None

    if len(reference_id) <= 8:
        return "****"

    return (
        "****"
        + reference_id[-8:]
    )


# ============================================================
# Parse verified Aadhaar XML
# ============================================================

def parse_verified_aadhaar(
    signed_root
):
    """
    Parse Aadhaar data only AFTER
    digital-signature verification.
    """

    if (
        etree.QName(
            signed_root
        ).localname
        != "OfflinePaperlessKyc"
    ):

        raise ValueError(
            "Signed document is not "
            "OfflinePaperlessKyc"
        )


    poi = signed_root.find(
        "./UidData/Poi"
    )

    poa = signed_root.find(
        "./UidData/Poa"
    )

    photo = signed_root.find(
        "./UidData/Pht"
    )


    if poi is None:

        raise ValueError(
            "Poi element missing"
        )


    reference_id = (
        signed_root.get(
            "referenceId"
        )
        or signed_root.get(
            "r"
        )
    )


    result = {

        "reference_id":
            reference_id,

        "name":
            poi.get("name"),

        "dob":
            poi.get("dob"),

        "gender":
            poi.get("gender"),

        "mobile_hash_present":
            bool(
                poi.get("m")
            ),

        "email_hash_present":
            bool(
                poi.get("e")
            ),

        "photo_present":
            bool(
                photo is not None
                and photo.text
                and photo.text.strip()
            ),

        "address":
            None,
    }


    if poa is not None:

        result["address"] = {

            "care_of":
                poa.get("careof"),

            "house":
                poa.get("house"),

            "street":
                poa.get("street"),

            "locality":
                poa.get("loc"),

            "vtc":
                poa.get("vtc"),

            "post_office":
                poa.get("po"),

            "district":
                poa.get("dist"),

            "subdistrict":
                poa.get("subdist"),

            "state":
                poa.get("state"),

            "country":
                poa.get("country"),

            "pincode":
                poa.get("pc"),
        }


    return result


# ============================================================
# Main Aadhaar processing workflow
# ============================================================

def process_aadhaar(
    zip_path: str,
    share_code: str,
    cert_path: str,
):

    # ------------------------------------------------
    # Step 1 - Validate UIDAI certificate trust
    # ------------------------------------------------

    print(
        "1. Verifying UIDAI "
        "PKI certificate chain..."
    )

    verify_certificate_chain(
        uidai_cert_path=cert_path,
        root_ca_path=str(
            ROOT_CA_PATH
        ),
        intermediates_path=str(
            INTERMEDIATES_PATH
        ),
    )

    print(
        "   PKI certificate chain: VALID"
    )

    print(
    "2. Checking UIDAI certificate revocation..."
)

    verify_certificate_revocation(
        uidai_cert_path=cert_path,
        crl_path=str(CRL_PATH),
        issuer_cert_path=str(SUBCA_CERT_PATH),
    )

    print(
        "   Certificate revocation check: PASSED"
    )

    # ------------------------------------------------
    # Step 3 - Read Aadhaar ZIP
    # ------------------------------------------------

    print(
        "3. Reading encrypted Aadhaar ZIP..."
    )

    xml_bytes = extract_xml_from_zip(
        zip_path,
        share_code
    )

    print(
        "   XML extracted successfully"
    )


    # ------------------------------------------------
    # Step 4 - Inspect XML Digital Signature
    # ------------------------------------------------

    print(
        "4. Inspecting digital signature..."
    )

    (
        signature_algorithm,
        digest_algorithm
    ) = inspect_signature_algorithm(
        xml_bytes
    )

    print(
        "   Signature algorithm:",
        signature_algorithm
    )

    print(
        "   Digest algorithm:",
        digest_algorithm
    )


    # ------------------------------------------------
    # Step 5 - Verify XML Digital Signature
    # ------------------------------------------------

    print(
        "5. Verifying UIDAI "
        "digital signature..."
    )

    verification = (
        verify_aadhaar_signature(
            xml_bytes,
            cert_path
        )
    )

    print(
        "   Signature verification: VALID"
    )


    # ------------------------------------------------
    # Step 6 - Parse verified Aadhaar data
    # ------------------------------------------------

    print(
        "6. Parsing verified Aadhaar data..."
    )

    kyc = parse_verified_aadhaar(
        verification["signed_xml"]
    )


    # ------------------------------------------------
    # Final result
    # ------------------------------------------------

    print(
        "\n--- Verification Result ---"
    )

    print(
        "PKI chain valid  : YES"
    )

    print(
        "Signature valid  : YES"
    )

    print(
        "Reference ID     :",
        mask_reference_id(
            kyc["reference_id"]
        )
    )

    print(
        "Name parsed      :",
        bool(kyc["name"])
    )

    print(
        "DOB parsed       :",
        bool(kyc["dob"])
    )

    print(
        "Gender parsed    :",
        bool(kyc["gender"])
    )

    print(
        "Photo present    :",
        kyc["photo_present"]
    )

    print(
        "Mobile hash      :",
        kyc["mobile_hash_present"]
    )

    print(
        "Email hash       :",
        kyc["email_hash_present"]
    )


    return kyc


# ============================================================
# Command-line entry point
# ============================================================

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

        print(
            "\nVerification FAILED"
        )

        print(
            type(exc).__name__
            + ": "
            + str(exc)
        )

        sys.exit(2)