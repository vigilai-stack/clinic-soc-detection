.PHONY: run test

run:
	PYTHONPATH=src python3 -m clinic_soc run

test:
	PYTHONPATH=src python3 -m pytest -q
