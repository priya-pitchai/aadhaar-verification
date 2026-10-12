from getpass import getpass

from kyc_verification import verify_investor_identity
from pan_verification.providers.mock_provider import MockPANVerifier


share_code = getpass(
    "Enter Aadhaar ZIP share code: "
)

pan_result, decision = verify_investor_identity(
    aadhaar_zip_path="test-data/offlineaadhaar.zip",
    share_code=share_code,
    uidai_cert_path="certs/uidai_offline_publickey_2026.cer",
    pan="ABCDE1234F",
    pan_verifier=MockPANVerifier(),
)

print("\n--- End-to-End KYC Result ---")
print("PAN provider :", pan_result.provider)
print("PAN status   :", pan_result.status.value)
print("Name match   :", pan_result.name_match)
print("DOB match    :", pan_result.dob_match)
print("Operative    :", pan_result.operative)
print("KYC decision :", decision.value)
