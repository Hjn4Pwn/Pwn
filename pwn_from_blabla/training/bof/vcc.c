#include <stdio.h>
#include <string.h>
// Hàm mã hóa và giải mã Canary
void encode_canary(unsigned long long *canary) {
    *canary = (*canary) ^ 0xDEADBEEF; // Ví dụ mã hóa
}
void decode_canary(unsigned long long *canary) {
    *canary = (*canary) ^ 0xDEADBEEF; // Ví dụ giải mã
}
void vuln(char *s)
{
    gets(s);
}
int main()
{
    unsigned long long canary = 0; // Khởi tạo giá trị Canary
    char a[10];
    // Mã hóa giá trị Canary trước khi sử dụng
    encode_canary(&canary);//canary = 0xDEADBEEF
    
    // Truyền giá trị Canary đã mã hóa vào hàm vuln
    vuln(a);
    // Giải mã giá trị Canary trước khi so sánh
    decode_canary(&canary);

    // Kiểm tra giá trị Canary sau khi hàm vuln đã thực thi
    if (canary != 0) {
        printf("Canary value changed! Possible buffer overflow detected.\n");
        exit(1);
    }
    printf("output: %s", a);
    return 0;
}
