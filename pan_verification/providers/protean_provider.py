from datetime import date, datetime, timezone
from uuid import uuid4

from pan_verification.models import PANVerificationResult
from pan_verification.validator import validate_pan_format


class ProteanPANVerifier:
    """
    PAN verification provider using Protean Online PAN Verification API.
    """

    API_VERSION = "4"

    def __init__(self, user_id: str):
        if not user_id:
            raise ValueError("Protean user_id cannot be empty")

        self.user_id = user_id

    def _build_request(
        self,
        pan: str,
        name: str,
        dob: date,
    ) -> dict:

        pan = validate_pan_format(pan)

        transaction_id = f"{self.user_id}:{uuid4().hex}"

        request_time = datetime.now(
            timezone.utc
        )

        request_data = {
            "User_ID": self.user_id,
            "Records_count": "1",
            "Request_time": request_time.isoformat(),
            "Transaction_ID": transaction_id,
            "Version": self.API_VERSION,
            "inputData": [
                {
                    "pan": pan,
                    "name": name.strip(),
                    "fathername": "",
                    "dob": dob.strftime("%d/%m/%Y"),
                }
            ],
            "signature": "",
        }

        return request_data