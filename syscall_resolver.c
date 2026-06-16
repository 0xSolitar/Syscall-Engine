#include "syscall_resolver.h"

FARPROC GetProcAddr(PVOID dllBytes, const char* apiName) {
    if (dllBytes == NULL) return NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDir = GetExportTable(dllBytes);
    if (pExportDir == NULL) return NULL;

    PDWORD pNames = (PDWORD)(dllBytes + pExportDir->AddressOfNames);
    PDWORD pAddresses = (PDWORD)(dllBytes + pExportDir->AddressOfFunctions);
    PWORD pOrdinals = (PWORD)(dllBytes + pExportDir->AddressOfNameOrdinals);
    for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++) {
        char* funcName = (char*)(dllBytes + pNames[i]);

        if (strcmp(apiName, funcName) == 0) {
            WORD ordinal = pOrdinals[i];
            PVOID pFuncAddr = (PVOID)((PBYTE)dllBytes + pAddresses[ordinal]);
            return (FARPROC)pFuncAddr;
        }
    }
    return NULL;
}

DWORD ExtractSSN(FARPROC funcAddr) {
    if (funcAddr == NULL) return NULL;

    PBYTE stub = (PBYTE)funcAddr;
    if (stub[0] == 0xB8) {
        DWORD ssn = *(DWORD*)(stub + 1);
        return ssn;
    }

    for (int i = 0; i < 16; i++) {
        if (stub[i] == 0xB8) {
            return *(DWORD*)(stub + i + 1);
        }
    }
    // not found
    return NULL;
}
