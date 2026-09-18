import unittest
from datetime import date

from pan_verification.models import (
    KYCDecision,
)
from pan_verification.policy import (
    evaluate_pan_result,
)
from pan_verification.providers.mock_provider import (
    MockPANVerifier,
)


class TestPANVerification(unittest.TestCase):

    def setUp(self):
        self.verifier = MockPANVerifier()

    def test_valid_pan_identity_match(self):

        result = self.verifier.verify(
            pan="ABCDE1234F",
            name="TEST INVESTOR",
            dob=date(1990, 1, 1),
        )

        decision = evaluate_pan_result(
            result
        )

        self.assertTrue(
            result.name_match
        )

        self.assertTrue(
            result.dob_match
        )

        self.assertEqual(
            decision,
            KYCDecision.VERIFIED,
        )

    def test_name_mismatch_requires_review(self):

        result = self.verifier.verify(
            pan="ABCDE1234F",
            name="DIFFERENT PERSON",
            dob=date(1990, 1, 1),
        )

        decision = evaluate_pan_result(
            result
        )

        self.assertFalse(
            result.name_match
        )

        self.assertTrue(
            result.dob_match
        )

        self.assertEqual(
            decision,
            KYCDecision.REVIEW_REQUIRED,
        )

    def test_dob_mismatch_requires_review(self):

        result = self.verifier.verify(
            pan="ABCDE1234F",
            name="TEST INVESTOR",
            dob=date(1991, 1, 1),
        )

        decision = evaluate_pan_result(
            result
        )

        self.assertTrue(
            result.name_match
        )

        self.assertFalse(
            result.dob_match
        )

        self.assertEqual(
            decision,
            KYCDecision.REVIEW_REQUIRED,
        )

    def test_pan_not_found(self):

        result = self.verifier.verify(
            pan="ABCDE1234H",
            name="TEST INVESTOR",
            dob=date(1990, 1, 1),
        )

        decision = evaluate_pan_result(
            result
        )

        self.assertEqual(
            decision,
            KYCDecision.REJECTED,
        )


if __name__ == "__main__":
    unittest.main()