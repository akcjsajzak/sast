# Offline SAST — build a single self-contained executable with an embedded
# vulnerability database.
#
#   make            # download feeds + build the executable (default)
#   make feeds      # download OSV feeds -> sast/data/advisories/downloaded.json
#   make build      # produce dist/sast (Linux) or dist/sast.exe (Windows)
#   make test       # run the unit test suite
#   make clean      # remove build artifacts
#
# The produced binary is fully offline: it contains the tool AND the downloaded
# advisory database. The default covers every language ecosystem OSV
# publishes a feed for; the OS distribution feeds (Alpine/Debian/Ubuntu, used
# for base-image scanning) are opt-in because of their size:
#   make feeds FEEDS="Packagist Maven npm PyPI Go NuGet Alpine Debian"

PYTHON      ?= python3
VENV        := .venv
FEEDS       ?= Packagist Maven npm PyPI Go NuGet
ADVISORY_DIR := sast/data/advisories
DOWNLOADED  := $(ADVISORY_DIR)/downloaded.json

# Host detection.
ifeq ($(OS),Windows_NT)
  EXE      := dist/sast.exe
  VENV_BIN := $(VENV)/Scripts
  SEP      := ;
else
  EXE      := dist/sast
  VENV_BIN := $(VENV)/bin
  SEP      := :
endif

.PHONY: all venv feeds build test clean

all: feeds build

venv:
	$(PYTHON) -m venv $(VENV)
	$(VENV_BIN)/python -m pip install --upgrade pip
	$(VENV_BIN)/pip install -e . pyinstaller

# Download OSV feeds and convert them to the internal advisory format so they
# get embedded into the binary by the `build` step.
feeds: venv
	$(VENV_BIN)/python -m sast.fetch_feeds --ecosystems $(FEEDS) -o $(DOWNLOADED)

build: venv
	$(VENV_BIN)/pyinstaller --onefile --clean --name sast \
	  --collect-all tree_sitter \
	  --collect-all tree_sitter_php \
	  --collect-all tree_sitter_java \
	  --add-data "$(ADVISORY_DIR)$(SEP)sast/data/advisories" \
	  sast/__main__.py
	@echo "Built: $(EXE)"

test: venv
	$(VENV_BIN)/python -m unittest tests.test_sast -v

clean:
	rm -rf build dist *.spec $(VENV)
