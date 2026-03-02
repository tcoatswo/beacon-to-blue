.PHONY: venv demo test

venv:
	python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt

demo:
	@echo "Generating artifacts + evaluation report..."
	python3 -m beacon_to_blue.cli --input spec/examples/http_beacon_minimal.yml --out out/artifacts
	python3 -m beacon_to_blue.evaluate --behavior spec/examples/http_beacon_minimal.yml \
	  --positive datasets/malicious_like/http_beacon_minimal.jsonl \
	  --benign datasets/benign/http_lookalike.jsonl \
	  --out out/report_http_beacon_minimal.json
	@echo "Report written to out/report_http_beacon_minimal.json"

test:
	pytest -q
