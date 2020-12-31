#pragma once
#include <Windows.h>

// 将content的内容保存到本地filepath文件中
INT write_file(CHAR* filepath, BYTE* content, UINT file_size);

// 从filepath文件中读取内容到缓冲区
BYTE* read_file(CHAR* filepath, UINT* file_size);
