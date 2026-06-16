#include "pe_parser.h"


PVOID LoadNtdllFromDisk() {
    HANDLE hFile = CreateFileA((LPSTR)"C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "failed to open ntdll: %ld", GetLastError());
        return NULL;
    }

    SIZE_T fileSize = GetFileSize(hFile, NULL);
    PVOID raw_bytes = malloc(fileSize);
    if (!ReadFile(hFile, raw_bytes, fileSize, NULL, NULL)) {
        fprintf(stderr, "failed to read ntdll bytes: %ld", GetLastError());
        CloseHandle(hFile);
        return NULL;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw_bytes;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "Invalid DOS header\n");
        free(raw_bytes);
        return NULL;
    }

    CloseHandle(hFile);
    return raw_bytes;
}

PIMAGE_EXPORT_DIRECTORY GetExportTable(PVOID pe_base) {
    if (pe_base == NULL) return NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pe_base;
    PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pe_base + pDosHeader->e_lfanew);
    DWORD export_rva = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (export_rva == 0) return NULL;

    return (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pe_base + export_rva);
}
