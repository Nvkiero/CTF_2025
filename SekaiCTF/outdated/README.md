Bài này mình không solve được trong giải tại quá tập trung vào cách setup vì bài này chương trình sử dụng một arch khá mới mipsrel6.
## Bug và phân tích:
Chương trình cho nhập 0x60 byte vào game_name(là một biến global).\
OOB bug:\
Chương trình cho nhập vào idx và nhập 2 byte vào.
## Exploit:
Ở đây bài sử dụng 1 thành ghi $gp(got pointer) trỏ vào got table khi muốn thực hiện các api thì sẽ -offset rồi jump tới got table thực thi api.\ 
Nhưng địa chỉ được load vào thành ghi này lại nằm đâu đó trên stack nên ta có thể thay đổi giá trị.\
Thêm việc ta ghi được vào biến global nên ta sẽ viết 1 fake got table rồi cho thành ghi trỏ vào vùng đó. -> leak libc -> call system.
