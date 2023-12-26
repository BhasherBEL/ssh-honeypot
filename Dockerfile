FROM golang:1.21.5 AS builder

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ssh-honeypot .

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/ssh-honeypot .

RUN mkdir data

ENV PATH data/ssh-honeypot.log
ENV PORT 22

EXPOSE 22
VOLUME /app/data

ENTRYPOINT ["./ssh-honeypot"]
