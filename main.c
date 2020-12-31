#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include "fileop.h"
#include "md5.h"
#include "rsa.h"
#include "pgp.h"


int main()
{
    HANDLE hHeap = GetProcessHeap();

    // 测速变量
    int test_times = 10;
    SYSTEMTIME start_time, end_time;
    double use_time = 0;
    int i = 0;

    // 要加密的文件路径
    char* plainpath = ".\\plain.txt";
    char* cipherpath = ".\\cipher.txt";
    char* decryptpath = ".\\decrypt.txt";

    // RSA公私钥文件路径
    char* rsa_sign_key = ".\\sign_key.prv";
    char* rsa_encrypt_key = ".\\encrypt_key.prv";

    BYTE* text_in = NULL;
    UINT text_length;
    BYTE* cipher = NULL;
    UINT cipher_len = 0;
    BYTE* text_out = NULL;
    UINT text_out_len = 0;

    // 读取明文
    text_in = read_file(plainpath, &text_length);
    printf("明文%s读取成功, 长度为%u字节\n", plainpath, text_length);

    // 创建密文和解密缓冲区
    cipher = calloc((size_t)text_length + (1 << 20), 1);
    text_out = calloc((size_t)text_length + 1024, 1);

    // 初始化pgp
    pgp_ctx_t pgp_ctx;
    pgp_init(&pgp_ctx, rsa_sign_key, rsa_encrypt_key);

    // PGP加密
    GetSystemTime(&start_time);
    for (i = 1; i <= test_times; i++)
    {
        pgp_encrypt(&pgp_ctx, text_in, text_length, cipher, &cipher_len);
    }
    GetSystemTime(&end_time);
    use_time = (end_time.wSecond - start_time.wSecond + 60) % 60 + (end_time.wMilliseconds - start_time.wMilliseconds) * 0.001;
    printf(
        "%d次PGP加密运算耗时%lfs, 平均速度为%.2lfMB/s\n",
        test_times, use_time,
        text_length / use_time * test_times / 1024 / 1024
    );
    write_file(cipherpath, cipher, cipher_len);
    printf("密文已保存到%s中\n", cipherpath);

#ifdef DEBUG

    printf("PGP加密结果为: ");
    for (i = 0; i < cipher_len; i++)
    {
        printf("%c", cipher[i]);
    }
    printf("\n");

#endif // DEBUG

    // PGP解密并验签
    int pgp_ret = 0;
    // PGP加密
    GetSystemTime(&start_time);
    for (i = 1; i <= test_times; i++)
    {
        pgp_ret = pgp_decrypt(&pgp_ctx, cipher, cipher_len, text_out, &text_out_len);
    }
    GetSystemTime(&end_time);
    use_time = (end_time.wSecond - start_time.wSecond + 60) % 60 + (end_time.wMilliseconds - start_time.wMilliseconds) * 0.001;
    printf(
        "%d次PGP解密运算耗时%lfs, 平均速度为%.2lfMB/s\n",
        test_times, use_time,
        text_length / use_time * test_times / 1024 / 1024
    );

    if (pgp_ret == PGP_SUCCESS)
    {
        write_file(decryptpath, text_out, text_out_len);
        printf("明文已保存到%s中\n", decryptpath);

#ifdef DEBUG

        printf("PGP解密结果为: ");
        for (i = 0; i < text_out_len; i++)
        {
            printf("%c", text_out[i]);
        }
        printf("\n");

#endif // DEBUG

    }
    else if(pgp_ret == PGP_ERROR_SIGN)
    {
        printf("签名错误\n");
    }
    else
    {
        printf("PGP未知错误\n");
    }

    free(cipher);
    free(text_out);
    HeapFree(hHeap, 0, text_in);
    return 0;
}
