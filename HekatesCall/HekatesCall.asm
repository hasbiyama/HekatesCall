;   author:
;   hasbiyama (@3xploitZero)
;   github.com/hasbiyama

section .text
    global sysInstruc
    
sysInstruc:
    syscall
    ret