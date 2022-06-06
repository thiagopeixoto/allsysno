PUBLIC currentSyscallNumber
PUBLIC SyscallDispatcher

.data
currentSyscallNumber DWORD 0

.code
SyscallDispatcher PROC
	mov	r10, rcx
	mov eax, currentSyscallNumber
	syscall
	ret
SyscallDispatcher ENDP

END