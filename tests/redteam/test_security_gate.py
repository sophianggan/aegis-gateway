import json
from pathlib import Path

import pytest

from aegis.security.input_guard import InputGuard
from aegis.security.output_guard import OutputGuard

CASES = json.loads((Path(__file__).parent / "cases.json").read_text())


@pytest.mark.redteam
@pytest.mark.parametrize("payload", CASES["ingress_attacks"])
def test_known_ingress_attacks_fail_closed(payload: str) -> None:
    result = InputGuard().inspect(payload)
    assert not result.safe, f"security gate allowed attack: {payload}"


@pytest.mark.redteam
@pytest.mark.parametrize("query", CASES["benign_queries"])
def test_normal_work_is_not_over_refused(query: str) -> None:
    result = InputGuard().inspect(query)
    assert result.safe, f"security gate over-refused benign query: {query}"


@pytest.mark.redteam
@pytest.mark.parametrize("payload", CASES["egress_attacks"])
def test_known_egress_patterns_fail_closed(payload: str) -> None:
    result = OutputGuard().scan(payload)
    assert not result.safe, f"security gate allowed egress pattern: {payload}"


@pytest.mark.redteam
def test_protected_value_exfiltration_fails_closed() -> None:
    protected = ["CASE-COPPER-7782", {"nested": "vault-passphrase"}]
    for payload in ("case-copper-7782", "The value is VAULT-PASSPHRASE"):
        assert not OutputGuard().scan(payload, protected_values=protected).safe
