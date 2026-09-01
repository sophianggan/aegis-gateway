from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from aegis.errors import PolicyViolationError


@dataclass(frozen=True)
class LeakFinding:
    kind: str
    fingerprint: str


@dataclass(frozen=True)
class OutputScan:
    safe: bool
    findings: tuple[LeakFinding, ...]


class OutputGuard:
    """Fail closed when a model response contains protected values or credentials."""

    _credential_patterns = (
        ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
        ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
        ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
        ("ssn", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
    )

    def __init__(self, max_output_characters: int = 32_000) -> None:
        if max_output_characters < 1:
            raise ValueError("max_output_characters must be positive")
        self._max_output_characters = max_output_characters

    @staticmethod
    def _fingerprint(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()[:12]

    @classmethod
    def _protected_strings(cls, values: list[Any]) -> set[str]:
        protected: set[str] = set()
        stack = list(values)
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                stack.extend(value.values())
            elif isinstance(value, (list, tuple, set, frozenset)):
                stack.extend(value)
            elif value is not None:
                candidate = str(value).strip()
                if len(candidate) >= 4:
                    protected.add(candidate)
        return protected

    def scan(self, output: str, *, protected_values: list[Any] | None = None) -> OutputScan:
        if len(output) > self._max_output_characters:
            finding = LeakFinding(
                kind="output_too_large",
                fingerprint=self._fingerprint(str(len(output))),
            )
            return OutputScan(safe=False, findings=(finding,))
        findings: list[LeakFinding] = []
        for kind, pattern in self._credential_patterns:
            for match in pattern.finditer(output):
                findings.append(
                    LeakFinding(kind=kind, fingerprint=self._fingerprint(match.group()))
                )

        for protected in self._protected_strings(protected_values or []):
            if protected.casefold() in output.casefold():
                findings.append(
                    LeakFinding(
                        kind="protected_value",
                        fingerprint=self._fingerprint(protected),
                    )
                )

        unique = tuple(dict.fromkeys(findings))
        return OutputScan(safe=not unique, findings=unique)

    def enforce(self, output: str, *, protected_values: list[Any] | None = None) -> OutputScan:
        result = self.scan(output, protected_values=protected_values)
        if not result.safe:
            raise PolicyViolationError(
                "model response blocked by output inspection",
                details={
                    "finding_count": len(result.findings),
                    "kinds": sorted({finding.kind for finding in result.findings}),
                },
            )
        return result
