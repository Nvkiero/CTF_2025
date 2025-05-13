FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

RUN apt update && \
    apt install -y socat 

WORKDIR /home/ctf
COPY escape /home/ctf/
COPY flag /

RUN chmod +x /home/ctf/escape

RUN useradd -m ctf && \
    chown -R root:ctf /home/ctf && \
    chmod 750 /home/ctf && \
    chmod 666 /

EXPOSE 1337

CMD ["socat", "tcp-listen:1337,reuseaddr,fork", "EXEC:/home/ctf/escape,stderr,su=ctf"]