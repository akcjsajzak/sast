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

# Grammars to bundle, derived from requirements.txt rather than listed by
# hand so adding a language cannot leave the list stale.
#
# PyInstaller's import analysis does currently find these on its own — a build
# with only the first three collected was verified to work for all eight
# languages — because each tree_sitter_* wheel ships its compiled extension as
# the module itself, which is picked up as a binary dependency. Collecting
# them explicitly is belt and braces: it also brings along any package data a
# grammar ships separately, which is not guaranteed to be found.
GRAMMARS := $(shell grep -oE '^tree_sitter[a-z_0-9]*' requirements.txt)
COLLECT  := $(foreach g,$(GRAMMARS),--collect-all $(g))

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
	@echo "Collecting grammars: $(GRAMMARS)"
	$(VENV_BIN)/pyinstaller --onefile --clean --name sast \
	  $(COLLECT) \
	  --add-data "$(ADVISORY_DIR)$(SEP)sast/data/advisories" \
	  sast/__main__.py
	@echo "Built: $(EXE)"

# Prove the frozen binary works. The unit tests exercise the Python package,
# not the executable, so a grammar missing from the bundle passes every test
# and still fails for users.
smoke:
	$(PYTHON) tests/smoke_binary.py $(EXE)

test: venv
	$(VENV_BIN)/python -m unittest tests.test_sast -v

clean:
	rm -rf build dist *.spec $(VENV)
