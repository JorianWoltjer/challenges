FROM rust:latest

RUN apt update && apt install -y socat

WORKDIR /app
COPY app .

RUN cargo install --path .

EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:conversationalist,stderr"]
