.PHONY: install lint test test-postgres run migrate demo

install:
	python -m pip install -e '.[dev]'

lint:
	ruff check .
	mypy src

test:
	pytest --cov --cov-report=term-missing

test-postgres:
	pytest -m postgres tests/postgres

run:
	uvicorn aegis.main:create_app --factory --reload

migrate:
	python -m aegis.cli migrate

demo:
	python examples/quickstart.py
