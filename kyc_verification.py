from datetime import date, datetime
from typing import Any

from verify_aadhaar import process_aadhaar
from pan_verification.interface import PANVerifier
from pan_verification.models import (
    KYCDecision,
    PANVerificationResult,
)
from pan_verification.policy import evaluate_pan_result


def parse_aadhaar_dob(value: Any) -> date:
    """
    Convert the DOB returned by Aadhaar parsing into datetime.date.

    Supports the common formats used in our PoC.
    """

    if isinstance(value, date):
        return value

    if not isinstance(value, str):
        raise ValueError("Aadhaar DOB is missing or invalid")

    value = value.strip()

    formats = (
        "%d-%m-%Y",
        "%d/%m/%Y",
        "%Y-%m-%d",
    )

    for fmt in formats:
        try:
            return datetime.strptime(
                value,
                fmt
            ).date()
        except ValueError:
            continue

    raise ValueError(
        f"Unsupported Aadhaar DOB format: {value}"
    )


def verify_investor_identity(
    aadhaar_zip_path: str,
    share_code: str,
    uidai_cert_path: str,
    pan: str,
    pan_verifier: PANVerifier,
) -> tuple[PANVerificationResult, KYCDecision]:

    # ------------------------------------------------
    # Step 1 - Cryptographically verify Aadhaar
    # ------------------------------------------------

    aadhaar_kyc = process_aadhaar(
        zip_path=aadhaar_zip_path,
        share_code=share_code,
        cert_path=uidai_cert_path,
    )

    # ------------------------------------------------
    # Step 2 - Obtain trusted Aadhaar identity fields
    # ------------------------------------------------

    aadhaar_name = (
        aadhaar_kyc.get("name") or ""
    ).strip()

    if not aadhaar_name:
        raise ValueError(
            "Verified Aadhaar does not contain a name"
        )

    aadhaar_dob = parse_aadhaar_dob(
        aadhaar_kyc.get("dob")
    )

    # ------------------------------------------------
    # Step 3 - Pass VERIFIED Aadhaar identity
    #          into PAN verification
    # ------------------------------------------------

    pan_result = pan_verifier.verify(
        pan=pan,
        name=aadhaar_name,
        dob=aadhaar_dob,
    )

    # ------------------------------------------------
    # Step 4 - Apply PAN/KYC policy
    # ------------------------------------------------

    decision = evaluate_pan_result(
        pan_result
    )

    return pan_result, decision
