Mình Hjn4 game vừa rồi mình solve được 2 challs Re, và nửa cái flag của chall thứ 3 ☹ đạt top 8/10. 

Mình chơi pwnable cơ mà lại k giải được câu pwn nào ==”

* Wanna One VPN

Mình Re khá là gà nên là lúc mở IDA lên bấm F5 thì nhận được cái này: 

**Decompilation failure: 126E: stack frame is too big**

Nên là mình phải dùng [Decompiler Online](https://dogbolt.org/) + đọc Asm

May là chall này khá dễ nên chưa cần đọc Asm lắm:

```c
int main()
{
    v13 = v15;
    do
    {
        v11 = v11;
    } while (stack_base + -0x1000 != stack_base + -2097168);
    v12 = v18[5];
    memset(&v10, 0x0, 0x1ffff0);

    init();
    printf("License key: ");
    v3 = read(0x0, &v4, 0x20);
    if (v3 <= 0)
        exit(0x1); 
    if (strlen(&v4) != strlen(encrypted_flag))
    {
        printf("Invalid license key!");
        exit(0x1); 
    }
    v2 = 0;
    while (true)
    {
        if (v2 < strlen(encrypted_flag))
        {
            if (*((char *)(v2 + encrypted_flag)) != (char)(v4 ^ 9))
            {
                printf("Invalid license key!");
                exit(0x1); 
            }
            v2 += 1;
        }
        else
        {
            puts("User authorized!");
            exit(0x0); 
        }
    }
}
```
Ở đây thì ta có thể thấy là chuỗi được nhập vào lưu ở **v4** với mỗi kí tự thì ta sẽ đem xor với 9 rồi so sánh với enc_flag ở vị trí tương ứng.

Do đó ta có thể xor ngược lại, bằng cách dùng mỗi kí tự của enc_flag xor 9 => real flag

Tuy nhiên ta cần tìm enc_flag trong file binary:

```shell
hjn4@LAPTOP-TEHHNDTG:/mnt/d/pwn_myself/WannaGame/vpn$ rabin2 -z wanna-one-vpn
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002004 0x00002004 24  25   .rodata ascii ^8rq9{Vd:VyesV~9|emVph6t
1   0x0000201d 0x0000201d 13  14   .rodata ascii License key:
2   0x0000202b 0x0000202b 20  21   .rodata ascii Invalid license key!
3   0x00002040 0x00002040 16  17   .rodata ascii User authorized!
```
### Exploit

```python
print(''.join(chr(ord(c) ^ 9) for c in "^8rq9{Vd:VyesV~9|emVph6t"))
```