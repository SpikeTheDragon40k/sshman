# Use official Go image with Go >= 1.23
FROM golang:1.23 as builder

WORKDIR /app

# Clone the repository
RUN git clone https://github.com/SpikeTheDragon40k/sshman.git . \
    && go mod tidy \
    && go build -o sshman

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates openssh-client xclip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /data

# Copy the compiled binary
COPY --from=builder /app/sshman /usr/local/bin/sshman

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sshman", "list"]
