#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <windows.h>
#include <stdio.h>

PVOID LoadNtdllFromDisk();
PIMAGE_EXPORT_DIRECTORY GetExportTable(PVOID image_base);
#endif
