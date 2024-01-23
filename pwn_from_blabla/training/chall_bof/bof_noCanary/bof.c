#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


void vuln(char* s){
    char buf[0x20];

    if(strlen(s) > 0x40){
        puts("Buffer too long!!");
        _exit(-1);
    }

    memcpy(buf,s,strlen(s));
}

int main(int argc, char** argv, char** envp){
    

    if(argc != 2){
        printf("Usage: %s <buffer>\n", argv[0]);
        return -1;
    }

    if(strlen(argv[1]) > 0x40){
        puts("Buffer too long!!");
        return -1;
    }
    vuln(argv[1]);

    return 0;
}

void w1n(){
    char* argv[] = { ":))", NULL};
    execve("/bin/sh",argv,NULL);
}