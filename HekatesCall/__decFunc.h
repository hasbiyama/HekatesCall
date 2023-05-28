/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include "__struct.h"

// // This function pointer type defines PIO_APC_ROUTINE that will be used in NtQueueApcThreadEx
// typedef VOID (*PIO_APC_ROUTINE) ( IN PVOID ApcContext, IN PIO_STATUS_BLOCK IoStatusBlock, IN ULONG Reserved);

__declspec(naked) NTSTATUS __cdecl SysLdrLoadDll(

  PWCHAR            PathToFile,
  ULONG             Flags,
  PUNICODE_STRING   ModuleFileName,
  PHANDLE           ModuleHandle,
  LPBYTE            funcAddr)
{
    __asm__ (
        "jmp %[funcAddr]"
        : // output operands
        : [funcAddr] "m" (funcAddr)
    );
}

__declspec(naked) NTSTATUS __cdecl SysLdrUnloadDll(
    HANDLE  ModuleHandle,
    LPBYTE  funcAddr) 
{
    __asm__ (
        "jmp %[funcAddr]"
        : // output operands
        : [funcAddr] "m" (funcAddr)
    );
}

__declspec(naked) NTSTATUS __cdecl SysRtlWow64GetThreadContext(
    HANDLE handle,
    WOW64_CONTEXT *context,
    LPBYTE  funcAddr) 
{
    __asm__ (
        "jmp %[funcAddr]"
        : // output operands
        : [funcAddr] "m" (funcAddr)
    );
}


__declspec(naked) NTSTATUS __cdecl SysNtAllocateVirtualMemory(
    HANDLE          ProcessHandle,
    PVOID           *BaseAddress,
    ULONG_PTR       ZeroBits,
    PSIZE_T         RegionSize,
    ULONG           AllocationType,
    ULONG           Protect,
    unsigned int    syscallNum,
    LPBYTE          p)
{
    __asm__ __volatile__ (
        "mov r10, rcx\n"
        "mov eax, %[syscallNum]\n"
        "jmp %[p]"
        : // output operands
        : [syscallNum] "m" (syscallNum), [p] "m" (p) // input operands
    );
}


__declspec(naked) NTSTATUS __cdecl SysNtProtectVirtualMemory(

    HANDLE          ProcessHandle,
    PVOID           *BaseAddress,
    PULONG          NumberOfBytesToProtect,
    ULONG           NewAccessProtection,
    PULONG          OldAccessProtection,
    LPBYTE          funcAddr,
    unsigned int    syscallNum,
    LPBYTE          p)
{
    __asm__ __volatile__ (
        "call %[funcAddr]\n"
        "mov eax, %[syscallNum]\n"
        "jmp %[p]"
        : // output operands
        : [funcAddr] "r" (funcAddr), [syscallNum] "m" (syscallNum), [p] "m" (p) // input operands
    );
}


__declspec(naked) HANDLE __cdecl SysNtCreateThreadEx(

    PHANDLE                 hThread,
    ACCESS_MASK             DesiredAccess,
    POBJECT_ATTRIBUTES      ObjectAttributes,
    HANDLE                  ProcessHandle, 
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    BOOL                    CreateSuspended,
    ULONG                   StackZeroBits,
    ULONG                   SizeOfStackCommit,
    ULONG                   SizeOfStackReserve,
    LPVOID                  lpBytesBuffer,
    LPBYTE                  funcAddr,
    unsigned int            syscallNum,
    LPBYTE                  p)

{
    __asm__ __volatile__ (
        "call %[funcAddr]\n"
        "mov eax, %[syscallNum]\n"
        "jmp %[p]"
        : // output operands
        : [funcAddr] "r" (funcAddr), [syscallNum] "m" (syscallNum), [p] "m" (p) // input operands
    );
}

__declspec(naked) NTSTATUS __cdecl SysNtWaitForSingleObject(
    HANDLE          Handle,
    BOOLEAN         Alertable,
    PLARGE_INTEGER  Timeout,
    LPBYTE          funcAddr,
    unsigned int    syscallNum,
    LPBYTE          p)
{
    __asm__ __volatile__ (
        "call %[funcAddr]\n"
        "mov eax, %[syscallNum]\n"
        "jmp %[p]"
        : // output operands
        : [funcAddr] "r" (funcAddr), [syscallNum] "m" (syscallNum), [p] "m" (p) // input operands
    );
}

__declspec(naked) NTSTATUS __cdecl SysNtFreeVirtualMemory(

    HANDLE          ProcessHandle,
    PVOID           *BaseAddress,
    PULONG          RegionSize,
    ULONG           FreeType,
    LPBYTE          funcAddr,
    unsigned int    syscallNum,
    LPBYTE          p)
{
    __asm__ __volatile__ (
        "call %[funcAddr]\n"
        "mov eax, %[syscallNum]\n"
        "jmp %[p]"
        : // output operands
        : [funcAddr] "r" (funcAddr), [syscallNum] "m" (syscallNum), [p] "m" (p) // input operands
    );
}

VOID movRCX() { __asm__("mov r10, rcx"); }