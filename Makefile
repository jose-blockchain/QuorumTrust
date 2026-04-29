.PHONY: build test lint fmt clean docs

# Default target
all: build

# Build the project
build:
	@echo "Building QuorumTrust..."
	cargo build --workspace

# Run tests
test:
	@echo "Running tests..."
	cargo test --workspace

# Lint with clippy
lint:
	@echo "Linting with clippy..."
	cargo clippy --workspace -- -D warnings

# Format code
fmt:
	@echo "Formatting code..."
	cargo fmt --workspace --check

# Clean build artifacts
clean:
	@echo "Cleaning..."
	cargo clean

# Run with logs
run:
	@echo "Starting QuorumTrust..."
	cargo run --workspace

# Generate documentation
docs:
	@echo "Generating docs..."
	cargo doc --workspace --no-deps --open

# Setup development environment
setup:
	@echo "Setting up development environment..."
	rustup component add clippy rustfmt
	cargo install cargo-deny 2>/dev/null || true
	@echo "Setup complete!"

# Pre-commit checks
pre-commit: fmt lint test
	@echo "All pre-commit checks passed!"

# Build release
release:
	@echo "Building release..."
	cargo build --workspace --release
