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
    if (ctx->syscall_table) {
        free(ctx->syscall_table);
        ctx->syscall_table = NULL;
    }
    if (ctx->ntdll_bytes) {
        free(ctx->ntdll_bytes);
        ctx->ntdll_bytes = NULL;
    }
    ctx->exports = NULL;
    ctx->table_size = 0;
}
