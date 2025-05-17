.PHONY: help clean test lint lint-check format format-dir

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
	@echo "  flake     - Run flake8 lint checking on source files"
	@echo "  lint      - Run Black lint check on all source files"
	@echo "  check     - Run Black lint check without modifying files"
	@echo "  format    - Format all source files with Black"
	@echo "  format-dir DIR=path/to/dir - Format files in specific directory"

clean:
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .coverage htmlcov/ .eggs/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

test:
	maturin develop
	$(PYTEST) -sv tests/

flake:
	flake8 py/safelz4/ -v --max-line-length 80

lint: 
	$(BLACK) $(BLACK_OPTS) $(SRC_DIRS)

check:
	$(BLACK) $(BLACK_OPTS) --check $(SRC_DIRS)

format: lint

format-dir:
	@if [ -z "$(DIR)" ]; then \
		echo "Error: DIR parameter is required. Usage: make format-dir DIR=path/to/dir"; \
		exit 1; \
	fi
	@if [ ! -d "$(DIR)" ]; then \
		echo "Error: Directory '$(DIR)' does not exist"; \
		exit 1; \
	fi
	$(BLACK) $(BLACK_OPTS) "$(DIR)"

# Install development dependencies
install-dev:
	$(PIP) install -e ".[dev]"

# Build the package
build:
	$(PIP) install .

build-exp:
	maturin build
	pip install -e .
