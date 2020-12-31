#pragma once
#include <stdlib.h>
#include <Windows.h>
#include <stdio.h>
#include "rsa.h"
#include "rsa.h"
#include "md5.h"
#include "idea.h"
#include "base64.h"

#define ZLIB_WINAPI
#include "zlib/zlib.h"
#pragma comment(lib, "zlib/zlibstat.lib")
#pragma comment(linker, "/NODEFAULTLIB:libc.lib")


// pgp�ṹ��
// �������ݹ�˽Կ
// �ӿڰ���
// ǩ+��
// ����+��ǩ
// ��ͬ�ķ���ֵ��ʾ��ͬ�Ľ��
// ����ֱ�Ӵ�ӡ���

#define PGP_SUCCESS       0x0
#define PGP_ERROR_ENCRYPT 0x1
#define PGP_ERROR_SIGN    0x2
#define PGP_ERROR_KEY     0x3
#define PGP_ERROR_UNZIP   0x4

typedef struct _pgp_ctx_t
{
    rsa_sk_t sk_sign;
    rsa_pk_t pk_sign;
    rsa_sk_t sk_encrypt;
    rsa_pk_t pk_encrypt;
} pgp_ctx_t;

void pgp_init(pgp_ctx_t* pgp_ctx, char* sign_key_path, char* encrypt_key_path);

int pgp_encrypt(pgp_ctx_t* pgp_ctx, BYTE* message, UINT message_length, BYTE* output, UINT* output_len);

int pgp_decrypt(pgp_ctx_t* pgp_ctx, BYTE* cipher, UINT cipher_length, BYTE* output, UINT* output_len);