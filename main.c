#include "syscall_engine.h"

int main() {
    SYSCALL_CONTEXT ctx;
    BOOL ok = InitSyscallContext(&ctx);

    if (!ok) {
        printf("failed to init syscall context");
        return 1;
    }
    printf("ctx initiated\n");

    if (!BuildSyscallTable(&ctx)) {
        CleanupSyscallContext(&ctx);
        printf("error building syscalltable");
        return 1;
    }

    printf("extracting ssn...");
    DWORD ssn = FindSSN(&ctx, "NtCreateFile");
    printf("NtCreateFile SSN: 0x%X (%lu)\n", ssn, ssn);
}
