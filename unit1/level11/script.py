from pwn import * 
import random 

p = process("./a.out")
time = p.recvline()
print(time)

p2 = process("./level11")
p2.sendline(time)
p2.interactive()

