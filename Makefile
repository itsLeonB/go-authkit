.PHONY: help lint test test-verbose test-coverage test-coverage-html test-clean build install-pre-push-hook uninstall-pre-push-hook

help:
	@echo "Makefile commands:"
	@echo "  make lint                    - Run golangci-lint on the codebase"
	@echo "  make test                    - Run all tests"
	@echo "  make test-verbose            - Run all tests with verbose output"
	@echo "  make test-coverage           - Run all tests with coverage report"
	@echo "  make test-coverage-html      - Run all tests and generate HTML coverage report"
	@echo "  make test-clean              - Clean test cache and run tests"
	@echo "  make build                   - Verify the module builds"
	@echo "  make install-pre-push-hook   - Install git pre-push hook"
	@echo "  make uninstall-pre-push-hook - Uninstall git pre-push hook"

lint:
	golangci-lint run ./...

test:
	@echo "Running all tests..."
	go test ./...

test-verbose:
	@echo "Running all tests with verbose output..."
	go test -v ./...

test-coverage:
	@echo "Running all tests with coverage report..."
	go test -v -coverprofile=coverage.out -covermode=atomic ./...

test-coverage-html:
	@echo "Running all tests and generating HTML coverage report..."
	go test -v -coverprofile=coverage.out ./... && \
	go tool cover -html=coverage.out -o coverage.html && \
	echo "Coverage report generated: coverage.html"

test-clean:
	@echo "Cleaning test cache and running tests..."
	go clean -testcache && go test -v ./...

build:
	@echo "Verifying build..."
	go build ./...
	@echo "Build OK"

install-pre-push-hook:
	@mkdir -p .git/hooks
	@cp scripts/git-pre-push.sh .git/hooks/pre-push
	@chmod +x .git/hooks/pre-push
	@echo "Pre-push hook installed successfully!"

uninstall-pre-push-hook:
	@rm -f .git/hooks/pre-push
	@echo "Pre-push hook uninstalled successfully!"
