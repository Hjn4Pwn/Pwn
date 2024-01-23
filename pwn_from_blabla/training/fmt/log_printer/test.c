#include <stdio.h>

int main() {
    char destination[9];  

    char source[30] = "flag.txt %1\$x AAAAAA.log";
    snprintf(destination, 15, "%s", source);

    printf("%s\n", destination);

    return 0;
}
