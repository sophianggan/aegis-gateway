from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

import asyncpg

from aegis.adapters.postgres import PostgresRecordRepository
from aegis.config import get_settings
from aegis.demo_data import DEMO_RECORDS
from aegis.domain.models import Classification
from aegis.security.identity import TokenAuthenticator


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="Aegis operator utilities")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate", help="apply ordered SQL migrations")
    commands.add_parser("seed", help="load non-sensitive demonstration records")
    token = commands.add_parser("token", help="issue a local development token")
    token.add_argument("--subject", default="local-developer")
    token.add_argument(
        "--clearance",
        choices=[item.name for item in Classification],
        default=Classification.CONFIDENTIAL.name,
    )
    token.add_argument("--compartment", action="append", default=[])
    token.add_argument("--role", action="append", default=[])
    return parser


def _load_migrations() -> list[tuple[str, str]]:
    root = Path(__file__).resolve().parents[2]
    return [(path.name, path.read_text()) for path in sorted((root / "migrations").glob("*.sql"))]


async def _migrate() -> None:
    settings = get_settings()
    connection = await asyncpg.connect(settings.database_url)
    try:
        migrations = await asyncio.to_thread(_load_migrations)
        for name, sql in migrations:
            await connection.execute(sql)
            print(f"applied {name}")
    finally:
        await connection.close()


async def _seed() -> None:
    settings = get_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=2)
    try:
        repository = PostgresRecordRepository(pool)
        for record in DEMO_RECORDS:
            await repository.put(record)
        print(f"loaded {len(DEMO_RECORDS)} demonstration records")
    finally:
        await pool.close()


def main() -> None:
    args = _parser().parse_args()
    if args.command == "migrate":
        asyncio.run(_migrate())
    elif args.command == "seed":
        asyncio.run(_seed())
    elif args.command == "token":
        settings = get_settings()
        token = TokenAuthenticator(settings).issue_development_token(
            subject=args.subject,
            clearance=Classification[args.clearance],
            compartments=set(args.compartment),
            roles=set(args.role),
        )
        print(token)


if __name__ == "__main__":
    main()
