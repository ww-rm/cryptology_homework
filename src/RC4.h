#pragma once

#include <Windows.h>

// RC4�㷨��S��ͼ����õ�ָ��S_I, S_J
static BYTE S[256] = { 0 };
static UINT S_I = 0, S_J = 0;

// ��ʼ��RC4�㷨��S���S��ָ��λ��
INT RC4_init(BYTE* key, UINT key_length);

// RC4�㷨�ļ��������
INT RC4(BYTE* in_text, BYTE* out_text, UINT text_length);
