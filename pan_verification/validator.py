import re


PAN_PATTERN = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")


def normalize_pan(pan: str) -> str:
    if not pan:
        raise ValueError("PAN cannot be empty")

    return pan.strip().upper()


def validate_pan_format(pan: str) -> str:
    normalized = normalize_pan(pan)

    if not PAN_PATTERN.fullmatch(normalized):
        raise ValueError(
            "Invalid PAN format. Expected format: AAAAA9999A"
        )

    return normalized


def mask_pan(pan: str) -> str:
    normalized = normalize_pan(pan)

    if len(normalized) != 10:
        return "**********"

    return normalized[:2] + "******" + normalized[-2:]