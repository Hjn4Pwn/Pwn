### pupu_0x61

Bài này đáng ra không khó đến mức hết giờ mà mình mới làm ra được nửa cái flag :))

Có vài lý do để mình thiếu nửa cái flag lúc hết giờ :(( 

* Vài cái lý do personal mà thầy Tự hay bảo 
* việc bỏ khá nhiều tgian ra ngẫm pwn cơ mà không giải đựoc câu nào 
* Python của mình còn quá non nớt
* Kỹ năng Re ...

Cơ mà sau 1 hồi fix cái code exploit thì nó cũng ra gì hơn khi nãy =="

Oke, với bài này mình cũng không thể đọc mã giả với IDA, bởi ***Decompilation failure: 126E: stack frame is too big***

Mình cũng không biết lý do là gì, tại mình không Re bao giờ kể từ khi xong Lab Re hệ thống. Cơ mà sau giải này mình hứa sẽ chơi luôn mảng Re :))

Ở chall này thì mình dùng [Decompiler Online](https://dogbolt.org/) + đọc Asm

```c
int main()
{
    printf("Enter vault key: ");
    v1 = read(0x0, &v3, 0x30);
    if (v1 <= 0)
        exit(0x1); 
    v3 = 0;
    if (strlen(&v3) != 32)
    {
        puts("Invalid vault key!");
        exit(0x1); 
    }
    v0 = 0;
    while (true)
    {
        if (v0 < strlen(&v3))
        {
            v2 = v3;
            v2 ^= v0;
            v2 *= 0x10000;
            if (((char)v0 & 1))
                v2 ^= 8304;
            else
                v2 ^= 28704;
            v2 ^= v0;
            if (v2 != *((long long *)(4202528 + 8 * v0)))
            {
                puts("Invalid vault key!");
                exit(0x1); 
            }
            v0 += 1;
        }
        else
        {
            puts("Vault authorized!");
            exit(0x0); 
        }
    }
}
```

Ban đầu đọc vào mình cứ bị cấn, chuỗi nhập vào được lưu ở *v3*, xong lại gán vào *v2* rồi mang v2 đi xor với byte ở vị trí **[4202528 + 8]** là như nào. Cơ mà sao một hồi lấn cấn thì mình quay lại đọc ASM, cùng với để ý kĩ ***long long***

Vừa đọc asm vừa đối chiếu để check xem tool decompile ổn không thì mọi thứ khá là khớp.

```shell
loc_14A5:
mov     eax, [rbp+var_2001D8]
cdqe
mov     rdx, [rbp+rax*8+var_2001D0]
mov     eax, [rbp+var_2001D8]
cdqe
xor     rdx, rax
mov     eax, [rbp+var_2001D8]
cdqe
mov     [rbp+rax*8+var_2001D0], rdx
mov     eax, [rbp+var_2001D8]
cdqe
mov     rdx, [rbp+rax*8+var_2001D0]
mov     eax, [rbp+var_2001D8]
cdqe
lea     rcx, ds:0[rax*8]
lea     rax, enc_flag
mov     rax, [rcx+rax]
cmp     rdx, rax
jz      short loc_1519
```
Đoạn này ở lệnh **cmp rdx, rax** thì ta xem **rax** lúc này đang chứa địa chỉ *enc_flag*, **rdx** check cả mã giả lẫn asm thêm liên kết với chuỗi *long long* ứng với 8 bytes ở trên thì có lẽ ta lấy 8 bytes của chuỗi nhập vào đem xor với 8 bytes của enc_flag ở vị trí tương ứng 

### enc_flag

```shell
.rodata:0000000000002020                 public enc_flag
.rodata:0000000000002020 enc_flag        db ' pW',0,0,0,0,0,'q 0',0,0,0,0,0,'"py',0,0,0,0,0,'s a',0,0,0,0,0,'$'
.rodata:0000000000002020                                         ; DATA XREF: main+282↑o
.rodata:0000000000002020                 db 'p5',0,0,0,0,0,'u q',0,0,0,0,0,'&pY',0,0,0,0,0,'w 7',0,0,0,0,0,'(p'
.rodata:0000000000002020                 db 'x',0,0,0,0,0,'y :',0,0,0,0,0,'*px',0,0,0,0,0,'{ j',0,0,0,0,0,',px'
.rodata:0000000000002020                 db 0,0,0,0,0,'} <',0,0,0,0,0,'.p>',0,0,0,0,0,7Fh,' a',0,0,0,0,0,'0pO',0
.rodata:0000000000002020                 db 0,0,0,0,'a g',0,0,0,0,0,'2ps',0,0,0,0,0,'c f',0,0,0,0,0,'4px',0,0,0
.rodata:0000000000002020                 db 0,0,'e a',0,0,0,0,0,'6pI',0,0,0,0,0,'g p',0,0,0,0,0,'8pw',0,0,0,0,0
.rodata:0000000000002020                 db 'i v',0,0,0,0,0,':p~',0,0,0,0,0,'k D',0,0,0,0,0,'<pv',0,0,0,0,0,'m'
.rodata:0000000000002020                 db ' -',0,0,0,0,0,'>p|',0,0,0,0,0,'o b',0,0,0,0,0
```

8 bytes tuy nhiên ta có thể bỏ qua byte *\x00* và đây là mã khai thác sau 1 hồi ngồi mò mẫm để nó trông ổn hơn :((

### Exploit

```python
byte_array = [b'Wp ', b'0 q', b'yp"', b'a s', 
            b'5p$', b'q u', b'Yp&', b'7 w', 
            b'xp(', b': y', b'xp*', b'j {', 
            b'xp,', b'< }', b'>p.', b'a o', 
            b'Op0', b'g a', b'sp2', b'f c', 
            b'xp4', b'a e', b'Ip6', b'p g', 
            b'wp8', b'v i', b'~p:', b'D k', 
            b'vp<', b'- m', b'|p>', b'b o']

v = []

for i in range(len(byte_array)):
    v.append(int.from_bytes(byte_array[i], byteorder='big', signed=True))

result = ""
for i in range(len(v)):
    v[i] ^= i
    if i & 1:
        v[i] ^= 8304
    else:
        v[i] ^= 28704
    v[i] //= 65536
    v[i] ^= i
    result += chr(v[i])

print(result)

```