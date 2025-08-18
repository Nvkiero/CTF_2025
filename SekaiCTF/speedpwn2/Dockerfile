FROM ubuntu@sha256:440dcf6a5640b2ae5c77724e68787a906afb8ddee98bf86db94eea8528c2c076

RUN apt-get update && \
    apt-get install -y socat && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY flag.txt /app/flag.txt
COPY chall /app/chall

EXPOSE 1337

USER nobody

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/app/chall
