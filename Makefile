.PHONY: setup lint test gate reproduce

setup:
	uv sync

lint:
	pre-commit run --all-files

test:
	pytest -q

gate:
	@echo "Smoke gates run in the smoke-test phase; see docs/EXPERIMENT_ARCHITECTURE_FINAL.md Part G"

reproduce:
	@echo "Available only after sealing; regenerates tables/figures from results/raw/"
