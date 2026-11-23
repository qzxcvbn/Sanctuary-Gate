# Stage 1: Build compilation environment
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy structural payload logic
COPY ./gateway/main.go .

# Compile the gateway filter framework
RUN CGO_ENABLED=0 GOOS=linux go build -o sanctuary_gateway main.go

# Stage 2: Final minimal runtime execution environment
FROM alpine:3.19

RUN apk add --no-cache curl

WORKDIR /root/

# Pull compiled binary from build stage
COPY --from=builder /app/sanctuary_gateway .

EXPOSE 8080

CMD ["./sanctuary_gateway"]