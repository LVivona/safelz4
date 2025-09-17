.PHONY: help clean test lint check fuzz flake format

# Define default Python and pip executables
PYTHON ?= python
PIP ?= pip
PYTEST ?= pytest
BLACK ?= black
BLACK_OPTS ?= --line-length 80 --target-version py35

# Source directories
SRC_DIRS ?= py/safelz4 tests

help:
	@echo "Available make targets:"
	@echo "  help      - Show this help message"
	@echo "  clean     - Remove build artifacts and cache files"
	@echo "  test      - Run all tests"
	@echo "  flake     - Run flake8 lint checking on source files (ignore: E302,E704,E301)"
	@echo "  fuzz	   - Run current fuzz target tests. e.g make fuzz TARGET=fuzz_roundtrip"
	@echo "  lint      - Run Black lint check on all source files"
	@echo "  check     - Run Black, flake8, and rustfmt lint check without modifying files"
	@echo "  format    - Format all source files with Black"

clean:
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .coverage htmlcov/ .eggs/ target/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

test:
	maturin develop
	$(PYTEST) -sv tests/

flake:
	flake8 py/safelz4/ -v --max-line-length 80
	flake8 py/safelz4/frame/__init__.pyi -v --max-line-length 80 --ignore=E302,E704,E301,F811
	flake8 py/safelz4/block/__init__.pyi -v --max-line-length 80 --ignore=E302,E704,E301

fuzz:
	@if [ -z "$(TARGET)" ]; then \
		echo "Error: TARGET parameter is required. Usage: make fuzz TARGET=fuzz_target_name"; \
		exit 1; \
	else \
		$(PYTHON) fuzz/$(TARGET).py; \
	fi

lint: 
	$(BLACK) $(BLACK_OPTS) $(SRC_DIRS)
	cargo fmt -- -v

check: flake
	$(BLACK) $(BLACK_OPTS) --check $(SRC_DIRS)
	cargo clippy -V
	cargo fmt -- --check -v
	

format: lint

build:
	$(PIP) install .

develop:
	maturin develop --release
