import sys
from pathlib import Path

from aegis import cli
from aegis.domain.models import Classification


def test_parser_accepts_operator_commands() -> None:
    parsed = cli._parser().parse_args(
        [
            "token",
            "--subject",
            "operator",
            "--clearance",
            "RESTRICTED",
            "--compartment",
            "operations",
            "--role",
            "auditor",
        ]
    )
    assert parsed.command == "token"
    assert parsed.clearance == "RESTRICTED"
    assert parsed.compartment == ["operations"]
    assert parsed.role == ["auditor"]


def test_load_migrations_returns_ordered_sql() -> None:
    migrations = cli._load_migrations()
    names = [name for name, _ in migrations]
    assert names == sorted(names)
    assert names == [
        "001_initial.sql",
        "002_database_roles.sql",
        "003_runtime_administration.sql",
    ]
    assert all(sql.startswith("BEGIN;") for _, sql in migrations)


def test_load_migrations_fails_loudly_when_assets_are_missing(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.chdir(tmp_path)
    installed_path = Path(tmp_path) / "installed" / "aegis" / "cli.py"
    monkeypatch.setattr(cli, "__file__", str(installed_path))
    try:
        cli._load_migrations()
    except FileNotFoundError as exc:
        assert "no SQL migrations found" in str(exc)
    else:
        raise AssertionError("missing migrations must not be treated as success")


def test_token_command_issues_authentic_local_token(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "aegis",
            "token",
            "--subject",
            "operator",
            "--clearance",
            "CONFIDENTIAL",
            "--compartment",
            "operations",
        ],
    )
    cli.main()
    token = capsys.readouterr().out.strip()
    principal = cli.TokenAuthenticator(cli.get_settings()).authenticate(f"Bearer {token}")
    assert principal.subject == "operator"
    assert principal.clearance == Classification.CONFIDENTIAL
    assert principal.compartments == {"operations"}
