from pwn import *
import os

DEBUG = True 
file = "./stack-ovfl-where-32"

# crash the process to get a core file and find the buffer address (still boilerplate)

io = process(file, env={}, setuid=False)
io.sendline(cyclic(10000)) 
io.wait()
core = io.corefile
buffer_address = core.stack.find(cyclic(50))
os.unlink(core.path) 

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env={}, gdbscript='''
b main
continue
''')

else:
    io = process(file, env={})


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

payload = b""
io.send(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
