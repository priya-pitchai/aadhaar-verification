import unittest
from datetime import date, datetime, timezone
from unittest.mock import patch

from pan_verification.providers.mock_provider import MockPANVerifier

from kyc_verification import verify_investor_identity

from pan_verification.models import (
    PANStatus,
    PANVerificationResult,
    KYCDecision,
)

from pan_verification.models import (
    PANStatus,
    KYCDecision,
    PANVerificationResult,
)


class CapturingPANVerifier:
    """
    Test verifier used only to prove that the verified
    Aadhaar name and DOB are passed into the PAN layer.
    """

    def __init__(self):
        self.received_pan = None
        self.received_name = None
        self.received_dob = None

    def verify(
        self,
        pan: str,
        name: str,
        dob: date
    ) -> PANVerificationResult:

        self.received_pan = pan
        self.received_name = name
        self.received_dob = dob

        return PANVerificationResult(
            pan=pan,
            provider="TEST",
            status=PANStatus.VALID,
            name_match=True,
            dob_match=True,
            operative=True,
            transaction_id="TEST-TXN-001",
            verified_at=datetime.now(
                timezone.utc
            ),
        )


class TestKYCIntegration(unittest.TestCase):

    @patch(
        "kyc_verification.process_aadhaar"
    )
    def test_verified_aadhaar_identity_passed_to_pan(
        self,
        mock_process_aadhaar,
    ):

        mock_process_aadhaar.return_value = {
            "name": "TEST INVESTOR",
            "dob": "01-01-1990",
        }

        verifier = CapturingPANVerifier()

        pan_result, decision = (
            verify_investor_identity(
                aadhaar_zip_path="dummy.zip",
                share_code="1234",
                uidai_cert_path="dummy.cer",
                pan="ABCDE1234F",
                pan_verifier=verifier,
            )
        )

        self.assertEqual(
            verifier.received_name,
            "TEST INVESTOR",
        )

        self.assertEqual(
            verifier.received_dob,
            date(1990, 1, 1),
        )

        self.assertEqual(
            verifier.received_pan,
            "ABCDE1234F",
        )

        self.assertEqual(
            decision,
            KYCDecision.VERIFIED,
        )

    @patch(
        "kyc_verification.process_aadhaar"
    )
    def test_matching_aadhaar_and_pan_returns_verified(
        self,
        mock_process_aadhaar,
    ):

        # Simulate successfully verified Aadhaar output.
        mock_process_aadhaar.return_value = {
            "name": "TEST INVESTOR",
            "dob": "01-01-1990",
        }

        verifier = MockPANVerifier()

        pan_result, decision = (
            verify_investor_identity(
                aadhaar_zip_path="dummy.zip",
                share_code="1234",
                uidai_cert_path="dummy.cer",
                pan="ABCDE1234F",
                pan_verifier=verifier,
            )
        )

        # PAN provider should confirm both
        # identity attributes match.
        self.assertTrue(
            pan_result.name_match
        )

        self.assertTrue(
            pan_result.dob_match
        )

        # PAN should be valid and operative.
        self.assertTrue(
            pan_result.operative
        )

        # Final KYC decision must be VERIFIED.
        self.assertEqual(
            decision,
            KYCDecision.VERIFIED,
        )

    @patch(
        "kyc_verification.process_aadhaar"
    )
    def test_name_mismatch_returns_review_required(
        self,
        mock_process_aadhaar,
    ):

        # Simulate successfully verified Aadhaar output
        # with a different name from the PAN record.
        mock_process_aadhaar.return_value = {
            "name": "DIFFERENT PERSON",
            "dob": "01-01-1990",
        }

        verifier = MockPANVerifier()

        pan_result, decision = (
            verify_investor_identity(
                aadhaar_zip_path="dummy.zip",
                share_code="1234",
                uidai_cert_path="dummy.cer",
                pan="ABCDE1234F",
                pan_verifier=verifier,
            )
        )

        # Name must fail.
        self.assertFalse(
            pan_result.name_match
        )

        # DOB still matches.
        self.assertTrue(
            pan_result.dob_match
        )

        # Mismatch must not become VERIFIED.
        self.assertEqual(
            decision,
            KYCDecision.REVIEW_REQUIRED,
        )

    @patch(
        "kyc_verification.process_aadhaar"
    )
    def test_dob_mismatch_returns_review_required(
        self,
        mock_process_aadhaar,
    ):

        # Simulate successfully verified Aadhaar output
        # where name matches but DOB differs.
        mock_process_aadhaar.return_value = {
            "name": "TEST INVESTOR",
            "dob": "01-01-1991",
        }

        verifier = MockPANVerifier()

        pan_result, decision = (
            verify_investor_identity(
                aadhaar_zip_path="dummy.zip",
                share_code="1234",
                uidai_cert_path="dummy.cer",
                pan="ABCDE1234F",
                pan_verifier=verifier,
            )
        )

        # Name should match.
        self.assertTrue(
            pan_result.name_match
        )

        # DOB should fail.
        self.assertFalse(
            pan_result.dob_match
        )

        # Mismatch must require manual review.
        self.assertEqual(
            decision,
            KYCDecision.REVIEW_REQUIRED,
        )

    @patch(
        "kyc_verification.process_aadhaar"
    )
    def test_pan_not_found_returns_rejected(
        self,
        mock_process_aadhaar,
    ):

        # Simulate successfully verified Aadhaar output.
        mock_process_aadhaar.return_value = {
            "name": "TEST INVESTOR",
            "dob": "01-01-1990",
        }

        verifier = MockPANVerifier()

        pan_result, decision = (
            verify_investor_identity(
                aadhaar_zip_path="dummy.zip",
                share_code="1234",
                uidai_cert_path="dummy.cer",
                pan="ABCDE1234H",
                pan_verifier=verifier,
            )
        )

        # PAN provider should report NOT_FOUND.
        self.assertEqual(
            pan_result.status,
            PANStatus.NOT_FOUND,
        )

        # Identity comparison is not meaningful
        # when the PAN record does not exist.
        self.assertIsNone(
            pan_result.name_match
        )

        self.assertIsNone(
            pan_result.dob_match
        )

        # Final KYC decision must be REJECTED.
        self.assertEqual(
            decision,
            KYCDecision.REJECTED,
        )

    @patch(
        "kyc_verification.process_aadhaar"
    )
    def test_aadhaar_failure_prevents_pan_verification(
        self,
        mock_process_aadhaar,
    ):

        # Simulate Aadhaar cryptographic verification failure.
        mock_process_aadhaar.side_effect = ValueError(
            "Aadhaar signature verification failed"
        )

        verifier = CapturingPANVerifier()

        # Aadhaar failure must propagate and stop the flow.
        with self.assertRaises(ValueError):
            verify_investor_identity(
                aadhaar_zip_path="tampered.zip",
                share_code="1234",
                uidai_cert_path="dummy.cer",
                pan="ABCDE1234F",
                pan_verifier=verifier,
            )

        # PAN verifier must never be called.
        self.assertIsNone(
            verifier.received_pan
        )

        self.assertIsNone(
            verifier.received_name
        )

        self.assertIsNone(
            verifier.received_dob
        )

if __name__ == "__main__":
    unittest.main()
