#!/bin/sh

# Make this executable with: chmod +x run.sh
socat TCP-LISTEN:1337,fork,reuseaddr EXEC:"/pwn/challenge",su=ctf