/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include "__decFunc.h"

// Defining function from assembly code
extern void sysInstruc();

// These function pointer types define the signature of Windows cryptography functions
typedef BOOL(WINAPI *CryptAcquireContextW_t) (HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD,DWORD);
typedef BOOL(WINAPI *CryptCreateHash_t) (HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
typedef BOOL(WINAPI *CryptHashData_t) (HCRYPTHASH hHash, const BYTE*, DWORD, DWORD);
typedef BOOL(WINAPI *CryptDeriveKey_t) (HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY*);
typedef BOOL(WINAPI *CryptDecrypt_t) (HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
typedef BOOL(WINAPI *CryptReleaseContext_t) (HCRYPTPROV, DWORD);
typedef BOOL(WINAPI *CryptDestroyHash_t) (HCRYPTHASH);
typedef BOOL(WINAPI *CryptDestroyKey_t) (HCRYPTKEY);

/*  Define the functions to read a value 
    from the TLS block for the current thread. */

#ifdef _WIN64
#define GetTEB() ((PTEB)__readgsqword(0x30))
#else
#define GetTEB() ((PTEB)__readfsdword(0x18))
#endif

PPEB GetPEB()
{
    PPEB peb = NULL;

#ifdef _WIN64
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif

    return peb;
}

// uintptr_t GetCurrentThreadIdViaTeb()
// {
//     PTEB teb = GetTEB();
//     if (teb != NULL)
//     {
//         return (uintptr_t)teb->ClientId.UniqueThread;
//     }
//     return(uintptr_t)-1;
// }

FARPROC GetXAddress(HMODULE hModule, LPCSTR lpProcName)
{
    // Get the module header
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);

    // Get the export directory
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Get the arrays of function names and addresses
    PDWORD pNameArray = (PDWORD)((LPBYTE)hModule + pExportDir->AddressOfNames);
    PDWORD pAddrArray = (PDWORD)((LPBYTE)hModule + pExportDir->AddressOfFunctions);
    PWORD pOrdArray = (PWORD)((LPBYTE)hModule + pExportDir->AddressOfNameOrdinals);

    // Search for the function name in the array of names
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR szName = (LPCSTR)((LPBYTE)hModule + pNameArray[i]);
        if (strcmp(szName, lpProcName) == 0) {
            // If the function name matches, return thecorresponding address from the address array
            return (FARPROC)((LPBYTE)hModule + pAddrArray[pOrdArray[i]]);
        }
    }

    // If the function name was not found, return NULL
    return NULL;
}

HMODULE ModuleXtract(LPCWSTR lpModuleName) {
    PPEB peb = GetPEB();
    PPEB_LDR_DATA ldr = peb->LoaderData;
    PLIST_ENTRY pListEntry = ldr->InLoadOrderModuleList.Flink;
    while (pListEntry != &ldr->InLoadOrderModuleList) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (_wcsicmp(pEntry->BaseDllName.Buffer, lpModuleName) == 0) {
            return pEntry->DllBase;
        }
        pListEntry = pListEntry->Flink;
    }
    return NULL;
}

void MoveXMemory(void* dest, const void* src, size_t size) {
    char* pDest = (char*)dest;
    const char* pSrc = (const char*)src;

    if (pDest <= pSrc || pDest >= pSrc + size) {
        // Non-overlapping memory regions
        while (size--) {
            *pDest++ = *pSrc++;
        }
    } else {
        // Overlapping memory regions, copy backwards to avoid data corruption
        pDest += size - 1;
        pSrc += size - 1;
        while (size--) {
            *pDest-- = *pSrc--;
        }
    }
}

void InitXUnicodeString(UNICODE_STRING* unicodeString, const wchar_t* wcharString) {
    size_t length = wcslen(wcharString);
    unicodeString->Length = (USHORT)(length * sizeof(wchar_t));
    unicodeString->MaximumLength = (USHORT)((length + 1) * sizeof(wchar_t));
    unicodeString->Buffer = (wchar_t*)wcharString;
}

int compareFunctionInfo(const void* a, const void* b) {
    const FunctionInfo* fa = (const FunctionInfo*)a;
    const FunctionInfo* fb = (const FunctionInfo*)b;
    if (fa->functionAddress < fb->functionAddress) {
        return -1;
    } else if (fa->functionAddress > fb->functionAddress) {
        return 1;
    } else {
        return 0;
    }
}

char* XOR_Dec(char *str) {
    char key = 0x0F;
    int len = strlen(str);
    for (int i = 0; i < len; i++) {
        str[i] ^= key;
    }
    return str;
}
