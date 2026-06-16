#include "syscall_resolver.h"

DWORD GetProcAddr(PVOID dllBytes, const char* apiName) {
    if (dllBytes == NULL) return 0;
    PIMAGE_EXPORT_DIRECTORY pExportDir = GetExportTable(dllBytes);
    if (pExportDir == NULL) return 0;

    PDWORD pNames = (PDWORD)((PBYTE)dllBytes + RVAToRawOffset(dllBytes, pExportDir->AddressOfNames));
    PDWORD pAddresses = (PDWORD)(dllBytes + RVAToRawOffset(dllBytes, pExportDir->AddressOfFunctions));
    PWORD pOrdinals = (PWORD)(dllBytes + RVAToRawOffset(dllBytes, pExportDir->AddressOfNameOrdinals));

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        DWORD nameRVA = pNames[i];
        DWORD nameRawOffset = RVAToRawOffset(dllBytes, nameRVA);
        if (nameRawOffset == 0) continue;

        char* funcName = (char*)((PBYTE)dllBytes + nameRawOffset);

        if (strcmp(apiName, funcName) == 0) {
            WORD ordinal = pOrdinals[i];
            DWORD funcRVA = pAddresses[ordinal];
            return funcRVA;
        }
    }
    return 0;
}

DWORD ExtractSSN(PVOID dllBase, DWORD funcRVA) {
    if (dllBase == NULL || funcRVA == 0) return 0;

    DWORD rawOffset = RVAToRawOffset(dllBase, funcRVA);
    if (rawOffset == 0) {
        printf("Coul not convert RVA 0x%X to raw offset\n", funcRVA);
        return 0;
    }

    PBYTE funcBytes = (PBYTE)dllBase + rawOffset;
    if (funcBytes[0] == 0xB8) {
        DWORD ssn = *(DWORD*)(funcBytes + 1);
        return ssn;
    }

    // fallback
    for (int i = 0; i < 32 && funcBytes[i] != 0xC3; i++) {
        if (funcBytes[i] == 0xB8) {
            return *(DWORD*)(funcBytes + i + 1);
        }
    }

    return 0;
}
