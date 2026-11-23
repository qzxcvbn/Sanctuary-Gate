# Stage 1: Build compilation environment
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy internal minting source code
COPY ./mint/main.go .

# Compile the execution oracle binary
RUN CGO_ENABLED=0 GOOS=linux go build -o sanctuary_mint main.go

# Stage 2: Minimal runtime deployment configuration
FROM alpine:3.19

RUN apk add --no-cache curl

WORKDIR /root/

COPY --from=builder /app/sanctuary_mint .

EXPOSE 8081

CMD ["./sanctuary_mint"]
