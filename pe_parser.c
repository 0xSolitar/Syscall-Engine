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
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, raw_bytes, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
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

PIMAGE_EXPORT_DIRECTORY GetExportTable(PVOID dllBytes) {
    if (dllBytes == NULL) return NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllBytes;
    PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)dllBytes + pDosHeader->e_lfanew);
    DWORD export_rva = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (export_rva == 0) return NULL;

    DWORD rawOffset = RVAToRawOffset(dllBytes, export_rva);
    if (rawOffset == 0) return NULL;

    return (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dllBytes + rawOffset);
}

DWORD RVAToRawOffset(PVOID dllBase, DWORD rva) {
    if (dllBase == NULL || rva == 0) return 0;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)dllBase + dos->e_lfanew);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (DWORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (rva >= section[i].VirtualAddress &&
            rva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
            DWORD offset = (rva - section[i].VirtualAddress) + section[i].PointerToRawData;
            return offset;
        }
    }
    return 0;
}
