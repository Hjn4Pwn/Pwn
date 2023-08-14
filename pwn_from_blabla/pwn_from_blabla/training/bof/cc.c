#include <stdio.h>
#include <string.h>

void vuln(char *s)
{
    gets(s);
}

int main()
{
    int b = 0;
    char a[10];
    
    vuln(a);
    if(b!=0)
        puts("win");
    printf("output: %s", a);
}
