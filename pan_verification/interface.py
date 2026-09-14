from datetime import date
from typing import Protocol

from pan_verification.models import PANVerificationResult


class PANVerifier(Protocol):

    def verify(
        self,
        pan: str,
        name: str,
        dob: date
    ) -> PANVerificationResult:
        """
        Verify PAN information using an authoritative
        or simulated verification provider.
        """

        ...