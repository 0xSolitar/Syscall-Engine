#ifndef SYSCALL_ENGINE_H
#define SYSCALL_ENGINE_H

#include <windows.h>
#include "pe_parser.h"

typedef struct {
    DWORD ssn;
    PVOID syscall_addr;
    CHAR* func_name;
} SYSCALL_ENTRY;

typedef struct {
    PVOID ntdll_bytes;
    PIMAGE_EXPORT_DIRECTORY exports;
    SYSCALL_ENTRY* syscall_table;
    DWORD table_size;
} SYSCALL_CONTEXT;

BOOL InitSyscallContext(SYSCALL_CONTEXT* ctx);
VOID CleanupSyscallContext(SYSCALL_CONTEXT* ctx);
#endif
