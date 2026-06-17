#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

PVOID LoadNtdllFromDisk();
PIMAGE_EXPORT_DIRECTORY GetExportTable(PVOID image_base);
DWORD RVAToRawOffset(PVOID dllBase, DWORD rva);
PVOID GetNtdllFromMemory();

typedef struct _LDR_DATA_TABLE_ENTRY_INTERNAL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_INTERNAL, *PLDR_DATA_TABLE_ENTRY_INTERNAL;

#endif
