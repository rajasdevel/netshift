# `check` runs offline. `lint` downloads its pinned tool on first use.
# CI runs `make lint`, so this pin is the only one.
STATICCHECK_VERSION := v0.8.2
OUTPUT ?= dist
FUZZTIME ?= 30s

.PHONY: build test fmt lint public-check check fuzz size-check smoke dist resources

# Writes bin/netshift; bin/ is ignored by git.
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o bin/netshift .

test:
	go test ./...

fmt:
	go fmt ./...

# The second pair analyzes the Windows build from this host. -exec sets GOOS
# for staticcheck alone, so the tool itself is still built for this host.
lint:
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...
	GOOS=windows go vet ./...
	go run -exec 'env GOOS=windows' honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

public-check:
	python3 scripts/check-public.py

check: public-check
	@unformatted="$$(gofmt -l $$(grep '\.go$$' release-files.txt))"; \
	if [ -n "$$unformatted" ]; then echo "Not gofmt-formatted (run make fmt):"; echo "$$unformatted"; exit 1; fi
	python3 scripts/test-release.py
	go test ./...
	go test -race ./...
	go vet ./...
	go run . --config config/example.json validate
	go run . --config config/azure.example.json validate
	go run . --config recipes/route53.json validate
	go run . --config recipes/webhook.json validate
	go run . --config recipes/restart-tunnel.json validate
	sh -n recipes/route53-ddns.sh recipes/webhook.sh recipes/restart-tunnel.sh

# Each fuzz target runs for FUZZTIME; their seeds also run in every go test.
fuzz:
	go test -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME) ./internal/config
	go test -run '^$$' -fuzz '^FuzzPublicIPv4$$' -fuzztime $(FUZZTIME) ./internal/config
	go test -run '^$$' -fuzz '^FuzzParseDevice$$' -fuzztime $(FUZZTIME) ./internal/engine
	go test -run '^$$' -fuzz '^FuzzHistoryTag$$' -fuzztime $(FUZZTIME) ./internal/engine

# Builds every release binary and fails if one is more than 10% larger than
# scripts/size-baseline.json (the v0.6.0 sizes).
size-check:
	python3 scripts/size-check.py

smoke: build
	python3 scripts/native-smoke.py --binary bin/netshift

dist:
	python3 scripts/release.py --output "$(OUTPUT)"

resources: build
	python3 scripts/resource-smoke.py --binary bin/netshift --seconds 60 --interval 5
