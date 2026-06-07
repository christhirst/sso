# Build stage
FROM docker.io/library/rust:1.88-slim AS builder

WORKDIR /usr/src/sso

# Install build dependencies (e.g. pkg-config, ssl, if needed for any crates)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Cargo.toml to cache dependency builds
COPY Cargo.toml ./

# Create dummy src/main.rs to build dependencies and cache them
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source files
COPY src ./src

# Rebuild the application binary in release mode
RUN cargo build --release

# Runtime stage
FROM docker.io/library/debian:bookworm-slim

WORKDIR /app

# Install runtime SSL certificates (required for secure outgoing HTTP requests)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from builder
COPY --from=builder /usr/src/sso/target/release/sso /app/sso

# Copy keys and configuration folder
COPY config /app/config
COPY src/private_key.pem /app/src/private_key.pem
COPY src/public_key.pem /app/src/public_key.pem

# Expose the port the server listens on
EXPOSE 3000

# Set environment to run the production build
ENV RUST_LOG=info

# Run the server
CMD ["/app/sso"]
