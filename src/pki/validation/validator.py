"""Certificate validator."""

from enum import Enum
from dataclasses import dataclass

class ValidationStatus(str, Enum):
    VALID = "VALID"
    BAD_FORMAT = "BAD_FORMAT"

@dataclass(frozen=True)
class ValidationResult:
    status: ValidationStatus
    message: str
    certificate = None

def validate_certificate(*_a, **_k):
    raise NotImplementedError
