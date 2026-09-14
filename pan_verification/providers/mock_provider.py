from datetime import date, datetime, timezone
from uuid import uuid4

from pan_verification.models import (
    PANStatus,
    PANVerificationResult,
)
from pan_verification.validator import validate_pan_format


class MockPANVerifier:

    def verify(
        self,
        pan: str,
        name: str,
        dob: date
    ) -> PANVerificationResult:

        pan = validate_pan_format(pan)

        transaction_id = str(uuid4())

        # Synthetic PoC scenarios only.
        if pan == "ABCDE1234F":
            return PANVerificationResult(
                pan=pan,
                provider="MOCK",
                status=PANStatus.VALID,
                name_match=True,
                dob_match=True,
                operative=True,
                transaction_id=transaction_id,
                verified_at=datetime.now(timezone.utc),
            )

        if pan == "ABCDE1234G":
            return PANVerificationResult(
                pan=pan,
                provider="MOCK",
                status=PANStatus.VALID,
                name_match=False,
                dob_match=True,
                operative=True,
                transaction_id=transaction_id,
                verified_at=datetime.now(timezone.utc),
            )

        if pan == "ABCDE1234H":
            return PANVerificationResult(
                pan=pan,
                provider="MOCK",
                status=PANStatus.NOT_FOUND,
                name_match=None,
                dob_match=None,
                operative=None,
                transaction_id=transaction_id,
                verified_at=datetime.now(timezone.utc),
            )

        return PANVerificationResult(
            pan=pan,
            provider="MOCK",
            status=PANStatus.UNKNOWN,
            name_match=None,
            dob_match=None,
            operative=None,
            transaction_id=transaction_id,
            verified_at=datetime.now(timezone.utc),
        )