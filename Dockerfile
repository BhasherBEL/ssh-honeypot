FROM golang:1.21.5 AS builder

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ssh-honeypot .

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/ssh-honeypot .

ENTRYPOINT ["./ssh-honeypot"]
