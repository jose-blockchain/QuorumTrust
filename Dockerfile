FROM rust:1.75 as builder

WORKDIR /app

# Copy Cargo.toml and lock file
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY . .

# Build the project
RUN cargo build --workspace --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/quorum-trust ./
COPY --from=builder /app/target/release/quorum-cli ./

# Copy configuration
COPY config/ ./config/

# Expose ports
EXPOSE 8080
EXPOSE 8081

# Run the application
CMD ["./quorum-trust"]
