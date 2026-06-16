#ifndef SYSCALL_RESOLVER_H
#define SYSCALL_RESOLVER_H

#include <windows.h>
#include <string.h>
#include "pe_parser.h"

DWORD ExtractSSN(FARPROC funcAddr);
FARPROC GetProcAddr(PVOID dllBytes, const char* funcName);

#endif
