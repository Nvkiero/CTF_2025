# Use the same OS version the binary was compiled on, e.g., ubuntu:24.04
FROM ubuntu:24.04

# Create a non-root user for the challenge to run as
RUN useradd --create-home --shell /bin/bash ctf

WORKDIR /pwn

# Install only socat, since the binary is pre-built
RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

# Copy your pre-built binary and flag
COPY ./challenge/ .

# --- Set file permissions ---
RUN chown -R root:root /pwn
RUN chmod 755 /pwn/challenge
# Set permissions: root can read/write, everyone else can only read.
RUN chown root:root /pwn/flag.txt && chmod 644 /pwn/flag.txt

# Copy and prepare the startup script
COPY ./run.sh /run.sh
RUN chmod +x /run.sh

EXPOSE 1337

# Executes the /bin/sh interpreter and passes the script to it
ENTRYPOINT ["/bin/sh", "/run.sh"]