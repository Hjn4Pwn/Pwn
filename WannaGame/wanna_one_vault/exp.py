byte_array = [b'Wp ', b'0 q', b'yp"', b'a s', 
            b'5p$', b'q u', b'Yp&', b'7 w', 
            b'xp(', b': y', b'xp*', b'j {', 
            b'xp,', b'< }', b'>p.', b'a o', 
            b'Op0', b'g a', b'sp2', b'f c', 
            b'xp4', b'a e', b'Ip6', b'p g', 
            b'wp8', b'v i', b'~p:', b'D k', 
            b'vp<', b'- m', b'|p>', b'b o']

v = []

for i in range(len(byte_array)):
    v.append(int.from_bytes(byte_array[i], byteorder='big', signed=True))

result = ""
for i in range(len(v)):
    v[i] ^= i
    if i & 1:
        v[i] ^= 8304
    else:
        v[i] ^= 28704
    v[i] //= 65536
    v[i] ^= i
    result += chr(v[i])

print(result)
