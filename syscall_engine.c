#include "syscall_engine.h"

BOOL InitSyscallContext(SYSCALL_CONTEXT *ctx) {
    memset(ctx, 0, sizeof(SYSCALL_CONTEXT));
    ctx->ntdll_bytes = GetNtdllFromMemory();
    if (!ctx->ntdll_bytes) {
        printf("ntdll failed to be loaded");
        return FALSE;
    }

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

    // Convert export table RVAs to raw offsets
    DWORD namesRawOffset = exports->AddressOfNames;
    DWORD addressesRawOffset = exports->AddressOfFunctions;
    DWORD ordinalsRawOffset = exports->AddressOfNameOrdinals;

    if (namesRawOffset == 0 || addressesRawOffset == 0 || ordinalsRawOffset == 0) {
        free(ctx->syscall_table);
        ctx->syscall_table = NULL;
        return FALSE;
    }

    PDWORD pNames = (PDWORD)((PBYTE)ctx->ntdll_bytes + namesRawOffset);
    PDWORD pAddresses = (PDWORD)((PBYTE)ctx->ntdll_bytes + addressesRawOffset);
    PWORD pOrdinals = (PWORD)((PBYTE)ctx->ntdll_bytes + ordinalsRawOffset);

    for (DWORD i = 0; i < ctx->table_size; i++) {
        // Convert name RVA to raw offset
        DWORD nameRawOffset = pNames[i];
        if (nameRawOffset == 0) continue;

        char* funcName = (char*)((PBYTE)ctx->ntdll_bytes + nameRawOffset);

        WORD ordinal = pOrdinals[i];
        DWORD funcRVA = pAddresses[ordinal];

        DWORD ssn = ExtractSSN(ctx->ntdll_bytes, funcRVA);

        ctx->syscall_table[i].ssn = ssn;
        ctx->syscall_table[i].syscall_addr = funcRVA;
        ctx->syscall_table[i].func_name = _strdup(funcName);
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
