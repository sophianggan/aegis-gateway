.PHONY: install lint test test-postgres run migrate demo clean clean-all

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

clean:
	$(RM) -r .coverage .coverage.* coverage.xml htmlcov dist build
	$(RM) -r .pytest_cache .mypy_cache .ruff_cache .hypothesis .tox .nox
	find src tests -type d -name __pycache__ -prune -exec $(RM) -r {} +
	find . -maxdepth 2 -type d -name '*.egg-info' -prune -exec $(RM) -r {} +
	$(RM) sbom.cdx.json image-digest.txt evidence-manifest.json

clean-all: clean
	$(RM) -r .venv infra/terraform/.terraform
