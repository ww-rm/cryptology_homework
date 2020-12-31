#include "fileop.h"

INT write_file(CHAR* filepath, BYTE* content, UINT file_size)
{
    // open content file
    HANDLE fp = CreateFileA(filepath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fp == INVALID_HANDLE_VALUE)
    {
        return -1;
    }

    DWORD write_count;
    if (WriteFile(fp, content, file_size, &write_count, NULL) == FALSE)
    {
        CloseHandle(fp);
        return -1;
    }

    CloseHandle(fp);
    return 0;
}

BYTE* read_file(CHAR* filepath, UINT* file_size)
{
    // open content file
    HANDLE fp = CreateFileA(filepath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fp == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    // get content length
    DWORD high_num = 0;
    *file_size = GetFileSize(fp, &high_num);
    if (high_num != 0)
    {
        CloseHandle(fp);
        return NULL;
    }

    // get content
    BYTE* content = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *file_size);
    if (content == NULL)
    {
        CloseHandle(fp);
        return NULL;
    }

    DWORD read_count;
    if (ReadFile(fp, content, *file_size, &read_count, NULL) == FALSE)
    {
        HeapFree(GetProcessHeap(), 0, content);
        CloseHandle(fp);
        return NULL;
    }

    CloseHandle(fp);
    return content;
}