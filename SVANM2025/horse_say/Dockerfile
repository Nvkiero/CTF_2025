FROM pwn.red/jail:0.3.0
COPY --from=ubuntu:24.04 / /srv
COPY bin/horse_say /srv/app/run
RUN chmod +x /srv/app/run
COPY bin/flag /srv/app/
EXPOSE 1337
ENV JAIL_TIME=15

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/bin/horse_say,stderr"]

