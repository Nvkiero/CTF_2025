## Bug và phân tích:
Trong khi tạo 1 pet xuất hiên lỗi heap overflow khi nhập tên cho pet:
``` c
    protected:
        char name[0x100];
        int age;
        int fullness;
        int status;
    public:
        void set_name() {
            std::cout << "Enter name: " << std::endl;
            std::cin >> this->name; // heap overflow
        }
```
Bài cho thêm một hàm print_pets() để in ra tên của pet (lợi dụng để leak các địa chỉ):
```c
void print_pets() {
    int cnt = 0;
    for(size_t i = 0; i < MAX_PET_COUNT; i++) {
        if(pets[i] != nullptr) {
            std::cout << cnt++ << ". " << pets[i]->get_name() << std::endl;
        }
    }
    return;
}
char* get_name() {
  return this->name;
}
```
## Exploit path:
1) Sử dụng heap overflow để leak libc: ghi đè chunk size > 0x421 để sau khi free chunk rơi vào unsorted bin -> leak libc.
2) Ở đây mình thực hiện leak stack rồi rop pop shell. -> mình tạo một pet trên vùng tcache thread rồi viết __libc_argv vào entry tcache 0x120 chunk để khi malloc thêm lần nữa sẽ update địa chỉ stack -> leak stack rồi rop
Bonus ở đây có thể exploit theo hướng khác là fake vtable được tạo cho từng con pet. (cách này không cần leak stack nhàn hơn rất nhiều). Sử dụng các gadget dưới
``` python
    # 0x00000000000984df : mov rdi, qword ptr [rdi + 0x10] ; call qword ptr [rax + 0x380]
    # 0x000000000002882f : ret
```


   


