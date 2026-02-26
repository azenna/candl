
.globl main
.type  main @function
main:
    push $0x7a # push z onto stack
    push %esp  # load into ebx
    pop  %ebx

    push $0x6d # load and assemble byte 1
    push $0x60
    pop  %eax
    pop  %ecx
    add  %ecx, %eax
    push %eax

    push $0x20 # load and assemble byte 2
    push $0x60
    pop  %eax
    pop  %ecx
    add  %ecx, %eax

    xor  %eax, 1(%esp) # instruction is on the stack

    push $0x31 # zero ecx edx
    pop  %eax
    xor  $0x31, %al
    push %eax
    push %eax
    pop  %ecx
    pop  %edx
    
    xor %ecx, %ecx
    je short $0x
