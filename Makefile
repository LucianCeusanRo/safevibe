.PHONY: run test lint fmt

run:
	safevibe serve

test:
	pytest -q

lint:
	ruff check src tests

fmt:
	ruff check --fix src tests
