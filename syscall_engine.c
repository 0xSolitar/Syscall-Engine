#include "syscall_engine.h"

BOOL InitSyscallContext(SYSCALL_CONTEXT *ctx) {
    memset(ctx, 0, sizeof(SYSCALL_CONTEXT));
    ctx->ntdll_bytes = LoadNtdllFromDisk();
    if (!ctx->ntdll_bytes) return FALSE;

    ctx->exports = GetExportTable(ctx->ntdll_bytes);
    if (!ctx->exports) {
        free(ctx->ntdll_bytes);
        return FALSE;
    }

    ctx->table_size = ctx->exports->NumberOfNames;
    ctx->syscall_table = calloc(ctx->table_size, sizeof(SYSCALL_ENTRY));
    if (!ctx->syscall_table) {
        free(ctx->ntdll_bytes);
        return FALSE;
    }

    return TRUE;
}

VOID CleanupSyscallContext(SYSCALL_CONTEXT *ctx) {
    if (ctx == NULL) return;

    if (ctx->syscall_table != NULL) {
        for (DWORD i = 0; i < ctx->table_size; i++) {
            if (ctx->syscall_table[i].func_name != NULL) {
                free(ctx->syscall_table[i].func_name);
            }
        }
        free(ctx->syscall_table);
        ctx->syscall_table = NULL;
    }

    if (ctx->ntdll_bytes != NULL) {
        free(ctx->ntdll_bytes);
        ctx->ntdll_bytes = NULL;
    }

    ctx->exports = NULL;
    ctx->table_size = 0;
}

BOOL BuildSyscallTable(SYSCALL_CONTEXT *ctx) {
    if (ctx == NULL || ctx->ntdll_bytes == NULL) return FALSE;

    PIMAGE_EXPORT_DIRECTORY exports = GetExportTable(ctx->ntdll_bytes);
    if (exports == NULL) return FALSE;

    ctx->exports = exports;
    ctx->table_size = exports->NumberOfNames;
    ctx->syscall_table = malloc(sizeof(SYSCALL_ENTRY) * ctx->table_size);
    if (ctx->syscall_table == NULL) return FALSE;

    PDWORD pNames = (PDWORD)((PBYTE)ctx->ntdll_bytes + exports->AddressOfNames);
    PDWORD pAddresses = (PDWORD)((PBYTE)ctx->ntdll_bytes + exports->AddressOfFunctions);
    PWORD pOrdinals = (PWORD)((PBYTE)ctx->ntdll_bytes + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < ctx->table_size; i++) {
        char* funcName = (char*)((PBYTE)ctx->ntdll_bytes + pNames[i]);

        WORD ordinal = pOrdinals[i];
        PVOID funcRVA = (PVOID)((PBYTE)ctx->ntdll_bytes + pAddresses[ordinal]);
        DWORD ssn = ExtractSSN((FARPROC)funcRVA);

        ctx->syscall_table[i].ssn = ssn;
        ctx->syscall_table[i].syscall_addr = funcRVA;
        ctx->syscall_table[i].func_name = strdup(funcName);
    }

    return TRUE;
}

DWORD FindSSN(SYSCALL_CONTEXT* ctx, const char* funcName) {
    if (ctx == NULL || ctx->syscall_table == NULL) return 0;

    for (DWORD i = 0; i < ctx->table_size; i++) {
        if (strcmp(ctx->syscall_table[i].func_name, funcName) == 0) {
            return ctx->syscall_table[i].ssn;
        }
    }
    return 0;
}
