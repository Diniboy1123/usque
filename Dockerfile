FROM golang:1.26.11-alpine AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -o usque -ldflags="-s -w" .

# scratch won't be enough, because we need a cert store
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/usque /bin/usque

ENTRYPOINT ["/bin/usque"]