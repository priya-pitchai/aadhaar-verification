from datetime import date, datetime, timezone
from uuid import uuid4

from pan_verification.models import (
    PANStatus,
    PANVerificationResult,
)
from pan_verification.validator import validate_pan_format


# ------------------------------------------------
# Synthetic PAN authority records for PoC testing.
# These are NOT real PAN records.
# ------------------------------------------------

MOCK_PAN_RECORDS = {
    "ABCDE1234F": {
        "name": "Priya P",
        "dob": date(1999, 4, 8),
        "status": PANStatus.VALID,
        "operative": True,
    },
}


def normalize_name(name: str) -> str:
    """
    Simple deterministic normalization for PoC matching.

    Example:
        " Test  Investor "
        -> "TEST INVESTOR"
    """

    return " ".join(
        name.upper().split()
    )


class MockPANVerifier:

    def verify(
        self,
        pan: str,
        name: str,
        dob: date
    ) -> PANVerificationResult:

        pan = validate_pan_format(pan)

        transaction_id = str(uuid4())
        verified_at = datetime.now(
            timezone.utc
        )

        # --------------------------------------------
        # Synthetic NOT_FOUND scenario
        # --------------------------------------------

        if pan == "ABCDE1234H":
            return PANVerificationResult(
                pan=pan,
                provider="MOCK",
                status=PANStatus.NOT_FOUND,
                name_match=None,
                dob_match=None,
                operative=None,
                transaction_id=transaction_id,
                verified_at=verified_at,
            )

        # --------------------------------------------
        # Look up simulated authoritative PAN record
        # --------------------------------------------

        record = MOCK_PAN_RECORDS.get(pan)

        if record is None:
            return PANVerificationResult(
                pan=pan,
                provider="MOCK",
                status=PANStatus.UNKNOWN,
                name_match=None,
                dob_match=None,
                operative=None,
                transaction_id=transaction_id,
                verified_at=verified_at,
            )

        # --------------------------------------------
        # Identity comparison
        # --------------------------------------------

        name_match = (
            normalize_name(name)
            == normalize_name(record["name"])
        )

        dob_match = (
            dob == record["dob"]
        )

        return PANVerificationResult(
            pan=pan,
            provider="MOCK",
            status=record["status"],
            name_match=name_match,
            dob_match=dob_match,
            operative=record["operative"],
            transaction_id=transaction_id,
            verified_at=verified_at,
        )