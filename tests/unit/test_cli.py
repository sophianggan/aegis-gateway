import sys

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
    assert names == ["001_initial.sql", "002_database_roles.sql"]
    assert all(sql.startswith("BEGIN;") for _, sql in migrations)


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
