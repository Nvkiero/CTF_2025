## Bug và phân tích:
checksec:
<img width="1085" height="357" alt="image" src="https://github.com/user-attachments/assets/0ab1fddb-53f2-48bd-82a4-8ab4910710f0" />
Phân tích:
Cho khả năng arw với 2 tham số nhập vào.
```c++
        switch(op) {
            case 'p':
                res = scanf("%d %d %hhx", &arg1, &arg2, &arg3);
                if(res != 3) {
                    puts("Invalid operation. 'h' for help");
                    flush_stdin();
                    break;
                }
                my_canvas.data[arg1*my_canvas.size_y + arg2] = arg3 ;
                break;
```
Chương trình cho mình malloc với 1 size bất kì với 2 số được nhập vào để làm size (option r).
```c++
            case 'r':
                res = scanf("%d %d", &arg1, &arg2);
                if(res != 2) {
                    puts("Invalid operation. 'h' for help");
                    flush_stdin();
                    break;
                }

                void *new_data = malloc(arg1 * arg2);
                if(new_data == NULL) {
                    puts("Internal Server Error");
                    exit(1);
                }
                free(my_canvas.data);
                my_canvas.data = new_data;
                my_canvas.size_x = arg2;
                my_canvas.size_y = arg1;
                clear_canvas(my_canvas);
```
## Exploit:
Vì chương trình không cho mình leak nhưng nên mình sử dụng tcache thread để malloc 1 chunk ở gần got table. \
Ban đầu mình định brute force hàm free thành system để system("/bin/sh") nhưng vì server chạy quá lâu nên mình đổi thành cách khác. \
Ở đây mình chuyển free[got] thành puts[plt] để chương trình sẽ call puts thay vì free địa chỉ sẽ in ra địa chỉ libc.  \
Có địa chỉ thì chuyển free -> system lấy flag. 


