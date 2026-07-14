.PHONY: setup lint test gate reproduce

setup:
	uv sync

lint:
	pre-commit run --all-files

test:
	pytest -q

gate:
	@test -n "$(GATE)" || (echo "usage: make gate GATE=g1"; exit 1)
	python smoke/$(GATE)/spike.py

reproduce:
	@echo "Available only after sealing; regenerates tables/figures from results/raw/"
