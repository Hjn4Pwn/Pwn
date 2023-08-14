#include <stdio.h>
#include <stdlib.h>

int vuln() {
    char buffer[64];

    puts("Leak me");
    read(0, buffer, 0x200);

    printf("%s \n",buffer);
    
return 0;
}

int main() {
    vuln();
    return 0;
}

void win() {
    puts("You won!");
}
