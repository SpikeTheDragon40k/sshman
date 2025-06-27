FROM golang:1.21-alpine AS builder

# Install Git
RUN apk add --no-cache git

# Clone the repo and build
WORKDIR /app
RUN git clone https://github.com/SpikeTheDragon40k/sshman.git . \
    && go mod tidy \
    && go build -o sshman

# Base image
FROM alpine:latest

# Install required tools: openssh for SSH, bash and xclip for clipboard
RUN apk add --no-cache openssh bash xclip

# Set working directory
WORKDIR /root/

# Copy the compiled binary
COPY --from=builder /app/sshman /usr/local/bin/sshman

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Entrypoint script will handle vault creation if needed
ENTRYPOINT ["/entrypoint.sh"]
