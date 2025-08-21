FROM legoclones/mips-pwn:mipsel32r6-musl

COPY outdated /target/ctf/chal
COPY flag.txt /target/ctf/flag.txt

RUN chmod +x /target/ctf/chal

EXPOSE 1337

CMD /start.sh