FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install gcc for CGO (SQLite)
RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY main.go vulnerabilities.json ./
RUN CGO_ENABLED=1 go build -o vulnapi main.go

FROM alpine:latest

WORKDIR /app

RUN apk add --no-cache libc6-compat

COPY --from=builder /app/vulnapi .
COPY --from=builder /app/vulnerabilities.json .

EXPOSE 3002

CMD ["./vulnapi"]
