VERSION ?= dev-$(shell ./release/dev-version.sh 2>/dev/null || echo unknown)
BUILD ?= undefined
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo undefined)
BUILD_TIME ?= $(shell date -u '+%Y%m%d-%H%M%S')
LDFLAGS = -X main.version=$(VERSION) -X main.build=$(BUILD) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)
TAG = v$(VERSION)
INSTALL_TEST_TIMEOUT ?= 1800
PYTEST_XDIST_WORKERS ?= 8
PYTEST_BUILTIN_WORKERS ?= 2
TEST_BINARY = $(if $(strip $(ZAIGR_TEST_BINARY)),$(abspath $(ZAIGR_TEST_BINARY)),$(CURDIR)/zaigr)

.PHONY: build lint lint-golang lint-python test-all test-prepare test-cli test-builtin test-versioning test-install test-release test-logged clean base-rootfs base-kernel clean-kernel

# Versioning tests temporarily edit embedded inputs; never overlap gate phases.
.NOTPARALLEL: test-all

# Build the base image, then compile the Go binary
build: base-kernel base-rootfs
	go build -ldflags "$(LDFLAGS)" -o zaigr ./cmd/zaigr

# Build the base image rootfs (skips if up to date)
base-rootfs:
	vm_prep/build-base-rootfs.sh

# Build the base image kernel (skips if up to date)
base-kernel:
	vm_prep/build-kernel.sh

lint: lint-golang lint-python

lint-golang:
	golangci-lint run ./cmd/zaigr/...

lint-python:
	ruff check tests release/release

test-prepare:
	@if [ -n "$(ZAIGR_TEST_BINARY)" ]; then \
		test -x "$(TEST_BINARY)" || { printf 'Missing executable test binary: %s\n' "$(TEST_BINARY)" >&2; exit 1; }; \
	else \
		$(MAKE) build; \
	fi

test-cli: test-prepare
	ZAIGR_TEST_BINARY="$(TEST_BINARY)" pytest -c tests/pytest.ini tests/cli -v -x -n $(PYTEST_XDIST_WORKERS) --maxschedchunk=1

test-builtin: test-prepare
	ZAIGR_TEST_BINARY="$(TEST_BINARY)" pytest -c tests/pytest.ini tests/builtin -v -x -n $(PYTEST_BUILTIN_WORKERS) --maxschedchunk=1 --timeout=1800 -o timeout_func_only=true

test-all: test-release test-versioning test-cli test-builtin test-install

test-release:
	pytest -c tests/pytest.ini tests/release -v -x

test-logged: test-prepare
	@if [ -z "$(strip $(TEST_PATH))" ]; then \
			echo "Usage: make test-logged TEST_PATH=<path-to-test>"; \
			exit 1; \
		fi
		ZAIGR_TEST_BINARY="$(TEST_BINARY)" pytest -c tests/pytest.ini $(TEST_PATH) -vv --timeout=600 -o timeout_func_only=true -s -o log_cli=true --log-cli-level=INFO

# Fast base image versioning checks
test-versioning:
	pytest -c tests/pytest.ini tests/versioning/test_versioning.py -v -x

test-install:
	pytest -c tests/pytest.ini tests/install -v -x --timeout=$(INSTALL_TEST_TIMEOUT) -o timeout_func_only=true

clean-kernel:
	rm -f cmd/zaigr/vm_data/bzImage

clean:
	rm -f zaigr
	rm -f cmd/zaigr/zaigr
	rm -f .cache/*.done
	rm -rf release/dist release/RELEASE_NOTES.md
	rm -f cmd/zaigr/vm_data/base-rootfs.img.zst
	rm -f cmd/zaigr/vm_data/bzImage
