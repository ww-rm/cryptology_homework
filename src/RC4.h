#pragma once

#include <Windows.h>

// RC4算法的S表和加密用的指针S_I, S_J
static BYTE S[256] = { 0 };
static UINT S_I = 0, S_J = 0;

// 初始化RC4算法的S表和S表指针位置
INT RC4_init(BYTE* key, UINT key_length);

// RC4算法的加密与解密
INT RC4(BYTE* in_text, BYTE* out_text, UINT text_length);
