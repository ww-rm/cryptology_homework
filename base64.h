#pragma once
/*base64.h*/
#ifndef _BASE64_H  
#define _BASE64_H  

#include <stdlib.h>  
#include <string.h>  
#include <Windows.h>

unsigned char* base64_encode(unsigned char* str, UINT str_len, BYTE* output, UINT* output_len);

unsigned char* base64_decode(unsigned char* code, UINT code_len, BYTE* output, UINT* output_len);

#endif