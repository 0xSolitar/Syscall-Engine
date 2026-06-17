#include "pe_parser.h"

PVOID GetNtdllFromMemory() {
#if defined(_WIN64)
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readgsqword(0x30);
#endif

    PPEB_LDR_DATA ldr = peb->Ldr;

    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY_INTERNAL entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_INTERNAL, InMemoryOrderLinks);
        if (entry->BaseDllName.Buffer != NULL && entry->BaseDllName.Length > 0) {
            if (_wcsicmp(entry->BaseDllName.Buffer, L"ntdll.dll") == 0) {
                return entry->DllBase;
            }
        }

        current = current->Flink;
    }

    return NULL;
}

PIMAGE_EXPORT_DIRECTORY GetExportTable(PVOID dllBytes) {
    if (dllBytes == NULL) return NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllBytes;
    PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)dllBytes + pDosHeader->e_lfanew);
    DWORD export_rva = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (export_rva == 0) return NULL;

    DWORD rawOffset = export_rva;
    if (rawOffset == 0) return NULL;
    return (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dllBytes + rawOffset);
}
