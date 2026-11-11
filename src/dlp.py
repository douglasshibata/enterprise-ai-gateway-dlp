import math
import re
from typing import Tuple, List, Dict

# High entropy threshold for secrets & API keys
SHANNON_ENTROPY_THRESHOLD = 4.5

HARD_BLOCK_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9_.\-]+", re.IGNORECASE),
    re.compile(r"(?:ghp_[a-zA-Z0-9]{36}|xox[baprs]-[a-zA-Z0-9\-]+)", re.IGNORECASE),
]

CPF_PATTERN = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
CREDIT_CARD_PATTERN = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")
IBAN_PATTERN = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def validate_luhn(card_number: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", card_number)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0

def validate_cpf(cpf_str: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", cpf_str)]
    if len(digits) != 11:
        return False
    if len(set(digits)) == 1:
        return False

    # Check digit 1
    s1 = sum(digits[i] * (10 - i) for i in range(9))
    d1 = (s1 * 10 % 11) % 10
    if digits[9] != d1:
        return False

    # Check digit 2
    s2 = sum(digits[i] * (11 - i) for i in range(10))
    d2 = (s2 * 10 % 11) % 10
    return digits[10] == d2

class DlpInspectionEngine:
    def check_hard_blocks(self, text: str) -> Tuple[bool, str]:
        """Returns: (is_blocked, reason)"""
        for pattern in HARD_BLOCK_PATTERNS:
            if pattern.search(text):
                return True, "Hard-block detected: Unsanitized database connection or cryptographic private key."

        # High entropy secret scanning on individual tokens
        words = text.split()
        for word in words:
            cleaned = word.strip("'\";:(),.")
            if len(cleaned) >= 20 and calculate_shannon_entropy(cleaned) >= SHANNON_ENTROPY_THRESHOLD:
                return True, f"Hard-block detected: High-entropy secret token identified (Entropy: {calculate_shannon_entropy(cleaned):.2f})."

        return False, ""

    def inspect_and_anonymize(self, text: str) -> Tuple[str, Dict[str, str]]:
        """
        Detects PII / financial entities and replaces them with reversible placeholders.
        Returns: (sanitized_text, token_mapping)
        """
        mapping: Dict[str, str] = {}
        sanitized = text

        # 1. Brazilian CPF
        for match in CPF_PATTERN.finditer(text):
            cpf_val = match.group(0)
            if validate_cpf(cpf_val):
                token = f"[CPF_{len(mapping)+1}]"
                mapping[token] = cpf_val
                sanitized = sanitized.replace(cpf_val, token)

        # 2. Credit Cards (Luhn)
        for match in CREDIT_CARD_PATTERN.finditer(sanitized):
            cc_val = match.group(0)
            if validate_luhn(cc_val):
                token = f"[CREDIT_CARD_{len(mapping)+1}]"
                mapping[token] = cc_val
                sanitized = sanitized.replace(cc_val, token)

        # 3. Emails
        for match in EMAIL_PATTERN.finditer(sanitized):
            email_val = match.group(0)
            token = f"[EMAIL_{len(mapping)+1}]"
            mapping[token] = email_val
            sanitized = sanitized.replace(email_val, token)

        return sanitized, mapping
