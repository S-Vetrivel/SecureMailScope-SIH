FROM golang:1.24-alpine AS builder

RUN apk add --no-舆 libpcap-dev tshark build-base

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /server ./cmd/server

FROM alpine:latest
RUN apk add --no-cache tshark ca-certificates

WORKDIR /app
COPY --from=builder /server /app/server

EXPOSE 8080
CMD ["/app/server"]
