from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum

from aegis.errors import PolicyViolationError


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class GuardFinding:
    rule: str
    severity: Severity


@dataclass(frozen=True)
class GuardResult:
    safe: bool
    findings: tuple[GuardFinding, ...]


class InputGuard:
    """Identify instructions attempting to override or inspect the model boundary."""

    _rules = (
        (
            "instruction_override",
            Severity.HIGH,
            re.compile(r"\b(ignore|disregard|override)\b.{0,40}\b(previous|prior|system)\b", re.I),
        ),
        (
            "secret_extraction",
            Severity.HIGH,
            re.compile(r"\b(reveal|print|return|show)\b.{0,40}\b(system prompt|secret|token|credential)", re.I),
        ),
        (
            "policy_bypass",
            Severity.HIGH,
            re.compile(r"\b(bypass|disable|evade)\b.{0,40}\b(policy|filter|guard|restriction)", re.I),
        ),
        (
            "role_reassignment",
            Severity.MEDIUM,
            re.compile(r"\b(you are now|act as|new instructions?)\b", re.I),
        ),
        (
            "prompt_delimiter",
            Severity.MEDIUM,
            re.compile(r"(<\|(?:system|assistant|user)\|>|\[/?INST\]|###\s*system)", re.I),
        ),
        (
            "encoded_payload",
            Severity.LOW,
            re.compile(r"\b(base64|rot13|hex[- ]?decode)\b", re.I),
        ),
    )

    def inspect(self, text: str) -> GuardResult:
        normalized = unicodedata.normalize("NFKC", text)
        findings = tuple(
            GuardFinding(rule=name, severity=severity)
            for name, severity, pattern in self._rules
            if pattern.search(normalized)
        )
        safe = not any(finding.severity == Severity.HIGH for finding in findings)
        return GuardResult(safe=safe, findings=findings)

    def enforce(self, text: str) -> GuardResult:
        result = self.inspect(text)
        if not result.safe:
            raise PolicyViolationError(
                "request contains unsafe model-control instructions",
                details={"rules": [finding.rule for finding in result.findings]},
            )
        return result

