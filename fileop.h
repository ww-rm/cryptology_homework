#pragma once
#include <Windows.h>

// ��content�����ݱ��浽����filepath�ļ���
INT write_file(CHAR* filepath, BYTE* content, UINT file_size);

// ��filepath�ļ��ж�ȡ���ݵ�������
BYTE* read_file(CHAR* filepath, UINT* file_size);
