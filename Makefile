SHELL := /bin/sh
.DEFAULT_GOAL := help
export GOTOOLCHAIN := go$(shell cat .go-version)
export GOFLAGS := -mod=readonly
TOOLS := $(CURDIR)/.tools/bin
STATICCHECK_VERSION := v0.8.2
GOVULNCHECK_VERSION := v1.10.0
XK6_VERSION := v1.5.1
ACTIONLINT_VERSION := v1.7.12
COMPAT_GO ?= $(shell cat .go-version)
COMPAT_K6 ?= $(shell go list -m -f '{{.Version}}' go.k6.io/k6/v2)
RELEASE_OUTPUT ?= bin/release-dry-run

.PHONY: help tools fmt lint arch test build verify smoke vuln hooks test-hooks deps e2e
help:
	@printf '%s\n' 'make tools   Install pinned verification tools' 'make fmt     Format Go source' 'make verify  Format, architecture, vet, staticcheck, race tests, build' 'make e2e     Run local SOAP HTTP fixtures with real k6' 'make e2e-race  Run signed multi-VU loopback with race-instrumented k6' 'make smoke   Build custom k6 and run positive/negative smoke tests' 'make compatibility  Verify the exact pinned k6 build, smoke and E2E' 'make release-dry-run  Rehearse Linux release packaging and audits' 'make vuln    Scan source and custom k6 binary (online advisory DB)' 'make fuzz-smoke  Run bounded SOAP and policy fuzz targets' 'make bench     Compare fixed performance and retention budgets on the pinned runner' 'make interop Run the independent Apache fixture (requires Docker)' 'make hooks   Install opt-in pre-commit hook without replacing existing hooks'

tools: $(TOOLS)/staticcheck $(TOOLS)/govulncheck $(TOOLS)/xk6 $(TOOLS)/actionlint
$(TOOLS)/staticcheck: Makefile .go-version
	@mkdir -p $(TOOLS)
	GOBIN=$(TOOLS) go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
$(TOOLS)/govulncheck: Makefile .go-version
	@mkdir -p $(TOOLS)
	GOBIN=$(TOOLS) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
$(TOOLS)/xk6: Makefile .go-version
	@mkdir -p $(TOOLS)
	GOBIN=$(TOOLS) go install go.k6.io/xk6/cmd/xk6@$(XK6_VERSION)

$(TOOLS)/actionlint: Makefile .go-version
	@mkdir -p $(TOOLS)
	GOBIN=$(TOOLS) go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

fmt:
	gofmt -w $$(git ls-files --cached --others --exclude-standard '*.go')
lint: $(TOOLS)/staticcheck $(TOOLS)/actionlint
	go test ./harness/archtest -run 'TestDeclarationStyle|TestRepositoryDeclarationStyle' -count=1
	@files=$$(gofmt -l $$(git ls-files --cached --others --exclude-standard '*.go')); if [ -n "$$files" ]; then printf 'Run make fmt:\n%s\n' "$$files"; exit 1; fi
	go vet ./...
	$(TOOLS)/staticcheck ./...
	$(TOOLS)/actionlint -shellcheck= -pyflakes=
	@for script in scripts/*.sh test/interop/wss4j/*.sh .githooks/pre-commit; do sh -n "$$script"; done
arch:
	go test ./harness/archtest -count=1
test:
	go test -race ./...
build:
	go build ./...
test-hooks:
	sh scripts/test-hooks.sh
deps:
	go mod tidy -diff
	go mod verify
verify: lint arch test build test-hooks deps perf-budget-test release-test

# Always rebuild: changes in any source or pin must be reflected in smoke tests.
.PHONY: build-k6
build-k6: $(TOOLS)/xk6
	@mkdir -p bin
	GOFLAGS= $(TOOLS)/xk6 build $$(go list -m -f '{{.Version}}' go.k6.io/k6/v2) --with github.com/stanimirivanov/xk6-soap=. --output bin/k6
smoke: build-k6
	sh scripts/smoke.sh
vuln: $(TOOLS)/govulncheck build-k6
	$(TOOLS)/govulncheck ./...
	$(TOOLS)/govulncheck -mode=binary bin/k6
hooks:
	sh scripts/install-hooks.sh

.PHONY: compatibility release-test release-dry-run
compatibility: build-k6
	python3 scripts/release.py bin/k6 "go$(COMPAT_GO)" "$(COMPAT_K6)"
	sh scripts/smoke.sh
	go test -race -tags=e2e ./test/e2e -count=1 -timeout=60s

release-test:
	PYTHONPATH=scripts PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/release

release-dry-run: $(TOOLS)/xk6 $(TOOLS)/govulncheck
	sh scripts/release-dry-run.sh "$(TOOLS)" "$(RELEASE_OUTPUT)" "$(XK6_VERSION)"

e2e: build-k6
	go test -race -tags=e2e ./test/e2e -count=1 -timeout=60s

.PHONY: build-k6-race test-e2e-race e2e-race
build-k6-race: $(TOOLS)/xk6
	@mkdir -p bin
	GOFLAGS= $(TOOLS)/xk6 build $$(go list -m -f '{{.Version}}' go.k6.io/k6/v2) --with github.com/stanimirivanov/xk6-soap=. --race-detector=1 --cgo=1 --output bin/k6-race

test-e2e-race:
	@go version -m bin/k6-race | awk '$$1 == "build" && $$2 == "-race=true" { race = 1 } $$1 == "build" && $$2 == "CGO_ENABLED=1" { cgo = 1 } END { if (!race || !cgo) { print "bin/k6-race must be built with race detection and cgo"; exit 1 } }'
	go test -race -tags=k6race ./test/e2e -run '^TestNativeK6RaceWorkload$$' -count=1 -timeout=75s

e2e-race: build-k6-race
	$(MAKE) test-e2e-race

.PHONY: interop
interop: build-k6
	sh scripts/interop.sh

.PHONY: fuzz-smoke
fuzz-smoke:
	sh scripts/fuzz-smoke.sh

.PHONY: bench perf-budget-test
bench: build-k6
	PYTHONDONTWRITEBYTECODE=1 python3 test/perf/run.py
perf-budget-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/perf -p test_budgets.py
