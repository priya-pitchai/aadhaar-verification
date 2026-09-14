from pan_verification.models import (
    PANStatus,
    KYCDecision,
    PANVerificationResult,
)


def evaluate_pan_result(
    result: PANVerificationResult,
) -> KYCDecision:

    # Provider/API failure
    if result.error_code:
        return KYCDecision.VERIFICATION_UNAVAILABLE

    # Clearly unacceptable authoritative states
    if result.status in {
        PANStatus.NOT_FOUND,
        PANStatus.DEACTIVATED,
        PANStatus.DELETED,
        PANStatus.INVALID,
    }:
        return KYCDecision.REJECTED

    # Unknown result should never become VERIFIED
    if result.status == PANStatus.UNKNOWN:
        return KYCDecision.REVIEW_REQUIRED

    # PAN exists but is currently not operative
    if result.operative is False:
        return KYCDecision.REVIEW_REQUIRED

    # Strong positive match
    if (
        result.status == PANStatus.VALID
        and result.name_match is True
        and result.dob_match is True
        and result.operative is True
    ):
        return KYCDecision.VERIFIED

    # PAN exists but identity attributes differ
    if (
        result.name_match is False
        or result.dob_match is False
    ):
        return KYCDecision.REVIEW_REQUIRED

    return KYCDecision.REVIEW_REQUIRED