from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class PANStatus(str, Enum):
    VALID = "VALID"
    NOT_FOUND = "NOT_FOUND"
    DEACTIVATED = "DEACTIVATED"
    DELETED = "DELETED"
    INVALID = "INVALID"
    UNKNOWN = "UNKNOWN"


class KYCDecision(str, Enum):
    VERIFIED = "VERIFIED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    REJECTED = "REJECTED"
    VERIFICATION_UNAVAILABLE = "VERIFICATION_UNAVAILABLE"


@dataclass
class PANVerificationResult:
    pan: str
    provider: str
    status: PANStatus

    name_match: Optional[bool]
    dob_match: Optional[bool]
    operative: Optional[bool]

    transaction_id: str
    verified_at: datetime

    error_code: Optional[str] = None
    error_message: Optional[str] = None