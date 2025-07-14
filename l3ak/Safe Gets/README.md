### Safe Gets:

![image](https://github.com/Nvkiero/CTF_2025/blob/main/l3ak/Safe%20Gets/Picture/Screenshot%202025-07-14%20101141.png)

## code: Reversed lại chương trình:
```c
  char s[259]; // [rsp+0h] [rbp-110h] BYREF
  char temp; // [rsp+103h] [rbp-Dh]
  int len; // [rsp+104h] [rbp-Ch]
  unsigned __int64 i; // [rsp+108h] [rbp-8h]

  gets(s);
  len = strlen(s);
  for ( i = 0LL; i < len / 2; ++i )
  {
    temp = s[len - 1 - i];
    s[len - 1 - i] = s[i];
    s[i] = temp;
  }
  puts("Reversed string:");
  puts(s);
  return 0;
```
Hàm win():
```c
int win()
{
  return system("/bin/sh");
}
```
## Solve in C:
Ở đây xuất hiện bug stack overflow ở hàm gets(), lại xuất hiện thêm một vòng for sử dụng return value từ hàm strlen() làm len để reversed lại string mà ta nhập vào (gây cản trở việc nhập payload). \
Hàm strlen(): đếm số byte xuất hiện của string cho đến khi gặp null byte. \
-> Bypass vòng for này bằng cách nhập NULL byte vào đầu thì len = 0, vòng for sẽ out ngay lập tức sau đó.
idea: Nhập một payload = NULL byte + padding + win.
```assembly
push    rbp
mov     rbp, rsp
lea     rax, command    ; "/bin/sh" <-------- win() + 8
mov     rdi, rax        ; command
call    _system
```
Ở đây để tránh việc stack không alignment ta nhảy thẳng vào hàm win() + 8.
## Bypass python script:
Ở đây vì ở server không thực sự chạy C file mà sử dụng python để nhập byte vào:
```python
BINARY = "./chall"
MAX_LEN = 0xff

# Get input from user
payload = input(f"Enter your input (max {MAX_LEN} bytes): ")
if len(payload) > MAX_LEN:
    print("[-] Input too long!")
    sys.exit(1)

# Start the binary with pipes
proc = subprocess.Popen(
    [BINARY],
    stdin=subprocess.PIPE,
    stdout=sys.stdout,
    stderr=subprocess.PIPE
)

try:
    # Send initial payload
    proc.stdin.write(payload.encode() + b'\n')
    proc.stdin.flush()
```
Ta thấy nó thực hiện qua đoạn check payload < 0xff(255) không thì sẽ exit. \

