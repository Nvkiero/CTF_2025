### The Goose:

<img width="840" height="666" alt="image" src="https://github.com/user-attachments/assets/7f18048b-5f44-49fc-af5d-1bde9bd442d7" />

## Revsersed C:
Ở đây chương trình sử dụng hàm time() để lấy thời gian thực thi chương trình làm seed cho hàm srand() rồi tạo số nhonks random từ 10->91
```c
  unsigned int seed; // eax

  setvbuf(_bss_start, 0LL, 2, 0LL);
  seed = time(0LL);
  srand(seed);
  setuser();
  nhonks = rand() % 91 + 10;
  if ( guess() )
    highscore();
  else
    puts("tough luck. THE GOOSE WINS! GET THE HONK OUT!");
  return 0;
```
Hàm setuser(): Nhập tên của người chơi
```c
 puts(
    "Welcome to the goose game.\n"
    "Here you have to guess a-priori, how many HONKS you will receive from a very angry goose.\n"
    "Godspeed.");
  printf("How shall we call you?\n> ");
  return __isoc99_scanf("%64s", username);
```
Sau đó vào hàm guess() để người chơi đoán số nhonks nếu đúng sẽ thực thi highscore().
```c
  int our_guess; // [rsp+8h] [rbp-8h] BYREF
  int i; // [rsp+Ch] [rbp-4h]

  our_guess = 0;
  i = 0;
  printf(
    "%s\n\nso %s. how many honks?",
    "\n"
    "                                                        _...--. \n"
    "                                        _____......----'     .' \n"
    "                                  _..-''                   .' \n"
    "                                .'                       ./ \n"
    "                        _.--._.'                       .' | \n"
    "                     .-'                           .-.'  / \n"
    "                   .'   _.-.                     .     ' \n"
    "                 .'  .'   .'    _    .-.        / `./  : \n"
    "               .'  .'   .'  .--' `.  |    |`. |     .' \n"
    "            _.'  .'   .' `.'       `-'    / |.'   .' \n"
    "         _.'  .-'   .'     `-.            `      .' \n"
    "       .'   .'    .'          `-.._ _ _ _ .-.    : \n"
    "      /    /o _.-'               .--'   .'      | \n"
    "    .'-.__..-'                  /..    .`    / .' \n"
    "  .'   . '                       /.'/.'     /  | \n"
    " `---'                                   _.'   ' \n"
    "                                       /.'    .' \n"
    "                                        /.'/.' \n",
    username);
  __isoc99_scanf("%d", &our_guess);
  putchar(10);
  for ( i = 0; i < nhonks; ++i )
    printf(" HONK ");
  putchar(10);
  return our_guess == nhonks;
```
Hàm highscore(): hàm này cho mình nhập message cho trò chơi và nhập lại tên của mình.
```c
  char buf[128]; // [rsp+0h] [rbp-170h] BYREF
  char s[128]; // [rsp+80h] [rbp-F0h] BYREF
  _BYTE fmt[32]; // [rsp+100h] [rbp-70h] BYREF
  char format[80]; // [rsp+120h] [rbp-50h] BYREF

  strcpy(format, "wow %s you're so good. what message would you like to leave to the world?");
  printf("what's your name again?");
  __isoc99_scanf("%31s", fmt);
  s[31] = 0;
  sprintf(s, format, fmt);
  printf(s);
  read(0, buf, 0x400uLL);
  return printf("got it. bye now.");
```
## Solve:
Ở đây xuất hiện một bug ở setuser() cho ta nhập hết phần username của chương trình rồi printf("%s", username) input ra màn hình cho đến khi xuất hiện NULL byte.
```assembly
.bss:0000000000004080 ; char username[64]
.bss:0000000000004080 username        db 40h dup(?)           ; DATA XREF: setuser+27↑o
.bss:0000000000004080                                         ; guess+16↑o
.bss:00000000000040C0                 public nhonks
.bss:00000000000040C0 nhonks          dd ?                    ; DATA XREF: guess:loc_1295↑r
.bss:00000000000040C0                                         ; guess+9C↑r ...
```
vì username và nhonks ở liền nhau nên ta có thể leak được số nhonks để khi vào hàm guess ta luôn đoán đúng được số nhonks.
-> Luôn thực thi hàm highscore().
Tiếp tục ở đây xuất hiện bug format string từ việc nhập lại tên và buffer overflow từ việc nhập message.
Sử dụng format string để leak libc và buffer overflow ROPgadget(ret2libc).
