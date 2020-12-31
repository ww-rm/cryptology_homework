#include "pgp.h"
//#define DEBUG

void pgp_init(pgp_ctx_t* pgp_ctx, char* sign_key_path, char* encrypt_key_path)
{
    rsa_get_sk_from_file(sign_key_path, &pgp_ctx->sk_sign, &pgp_ctx->pk_sign);
    rsa_get_sk_from_file(encrypt_key_path, &pgp_ctx->sk_encrypt, &pgp_ctx->pk_encrypt);
}

int pgp_encrypt(pgp_ctx_t* pgp_ctx, BYTE* message, UINT message_length, BYTE* output, UINT* output_len)
{

    // 计算md5摘要
    MD5_CTX md5_ctx;
    BYTE m_md5[16];
    MD5Init(&md5_ctx);
    MD5Update(&md5_ctx, message, message_length);
    MD5Final(&md5_ctx, m_md5);

#ifdef DEBUG

    UINT i;
    printf("MD5运算结果为: ");
    for (i = 0; i < 16; i++)
    {
        printf("%02X ", m_md5[i]);
    }
    printf("\n");

#endif // DEBUG

    // 计算RSA对md5的签名m_sign
    BYTE m_sign[512];
    UINT m_sign_len = 0;

    rsa_private_encrypt(m_sign, &m_sign_len, m_md5, 16, &pgp_ctx->sk_sign);

#ifdef DEBUG

    printf("RSA签名结果为: ");
    for (i = 0; i < pgp_ctx->sk_sign.bits / 8; i++)
    {
        printf("%02X ", m_sign[i]);
    }
    printf("\n");

#endif // DEBUG


    // 合并message和sign, 并进行zip压缩
    UINT m_merge_len = message_length+m_sign_len;
    BYTE* m_merge = calloc(m_merge_len, 1);
    memcpy(m_merge, message, message_length);
    memcpy(m_merge + message_length, m_sign, m_sign_len);

    UINT m_zip_len = 2*m_merge_len;
    BYTE* m_zip = calloc(m_zip_len, 1);
    compress(m_zip, &m_zip_len, m_merge, m_merge_len);

#ifdef DEBUG

    printf("ZIP压缩结果为: ");
    for (i = 0; i < m_zip_len; i++)
    {
        printf("%02X ", m_zip[i]);
    }
    printf("\n");

#endif // DEBUG

    // IDEA(zip())
    BYTE idea_key[17] = "1234567812345678";
    UINT m_cipher_len = m_zip_len + 4096;
    BYTE* m_cipher = calloc(m_cipher_len, 1);
    idea_encrypt_all(m_zip, m_zip_len, idea_key, m_cipher, &m_cipher_len);

#ifdef DEBUG

    printf("IEDA加密结果为: ");
    for (i = 0; i < m_cipher_len; i++)
    {
        printf("%02X ", m_cipher[i]);
    }
    printf("\n");

#endif // DEBUG

    // RSA(key)
    BYTE encrypted_idea_key[512];
    UINT encrypted_idea_key_len = 512;

    rsa_public_encrypt(encrypted_idea_key, &encrypted_idea_key_len, idea_key, 16, &pgp_ctx->pk_encrypt);

#ifdef DEBUG

    printf("RSA加密结果为: ");
    for (i = 0; i < pgp_ctx->pk_encrypt.bits / 8; i++)
    {
        printf("%02X ", encrypted_idea_key[i]);
    }
    printf("\n");

#endif // DEBUG

    // b64(<IDEA, RSA(key)>)
    UINT m_final_len = m_cipher_len + encrypted_idea_key_len;
    BYTE* m_final = m_cipher;
    memcpy(m_final + m_cipher_len, encrypted_idea_key, encrypted_idea_key_len);

    base64_encode(m_final, m_final_len, output, output_len);

#ifdef DEBUG

    printf("base64编码结果为: ");
    for (i = 0; i < *output_len; i++)
    {
        printf("%c", output[i]);
    }
    printf("\n");

#endif // DEBUG

    free(m_merge);
    free(m_zip);
    free(m_cipher);

    return 0;
}

int pgp_decrypt(pgp_ctx_t* pgp_ctx, BYTE* cipher, UINT cipher_length, BYTE* output, UINT* output_len)
{
    // base64解码
    int ret = PGP_SUCCESS;
    UINT i = 0;
    UINT m_final_len = cipher_length;
    BYTE* m_final = (BYTE*)calloc(m_final_len + 10, 1);

    base64_decode(cipher, cipher_length, m_final, &m_final_len);

#ifdef DEBUG

    printf("base64解码结果为: ");
    for (i = 0; i < m_final_len; i++)
    {
        printf("%02X ", m_final[i]);
    }
    printf("\n");

#endif // DEBUG

    // rsa解密IDEA密钥
    UINT m_cipher_len = m_final_len - (pgp_ctx->sk_encrypt.bits / 8);
    BYTE* m_cipher = m_final;

    BYTE idea_key[16 + 512];
    UINT idea_key_len = 16;

    rsa_private_decrypt(
        idea_key, &idea_key_len,
        m_final + m_cipher_len, pgp_ctx->sk_encrypt.bits / 8,
        &pgp_ctx->sk_encrypt
    );

#ifdef DEBUG

    printf("RSA解密结果为: ");
    for (i = 0; i < idea_key_len; i++)
    {
        printf("%02X ", idea_key[i]);
    }
    printf("\n");

#endif // DEBUG

    // IDEA解密
    UINT m_plain_len = m_final_len;
    BYTE* m_plain = (BYTE*)calloc(m_plain_len + 1024, 1);
    idea_decrypt_all(m_cipher, m_cipher_len, idea_key, m_plain, &m_plain_len);

#ifdef DEBUG

    printf("IEDA解密结果为: ");
    for (i = 0; i < m_plain_len; i++)
    {
        printf("%02X ", m_plain[i]);
    }
    printf("\n");

#endif // DEBUG

    // zip解压
    UINT m_unzip_len = 1000 * m_plain_len;
    BYTE* m_unzip = (BYTE*)calloc(m_unzip_len, 1);
    if (uncompress(m_unzip, &m_unzip_len, m_plain, m_plain_len) == Z_OK)
    {

#ifdef DEBUG
        printf("ZIP解压缩结果为: ");
        for (i = 0; i < m_unzip_len; i++)
        {
            printf("%02X ", m_unzip[i]);
        }
        printf("\n");

#endif // DEBUG

        // 验签
        UINT message_len = m_unzip_len - (pgp_ctx->pk_sign.bits / 8);
        BYTE* message = m_unzip;

        // 解密出HASH值
        BYTE m_unsign[1024] = { 0 };
        UINT m_unsign_len = 0;
        rsa_public_decrypt(
            m_unsign, &m_unsign_len,
            m_unzip + message_len, pgp_ctx->pk_sign.bits / 8,
            &pgp_ctx->pk_sign
        );

#ifdef DEBUG

        printf("RSA解签结果为: ");
        for (i = 0; i < m_unsign_len; i++)
        {
            printf("%02X ", m_unsign[i]);
        }
        printf("\n");

#endif // DEBUG

        // 计算当前HASH
        MD5_CTX md5_ctx;
        BYTE m_md5[16];
        MD5Init(&md5_ctx);
        MD5Update(&md5_ctx, message, message_len);
        MD5Final(&md5_ctx, m_md5);

        if (memcmp(m_md5, m_unsign, 16) == 0)
        {
            memcpy(output, message, message_len);
            *output_len = message_len;
            ret = PGP_SUCCESS;
        }
        else
        {
            ret = PGP_ERROR_SIGN;
        }
    }
    else
    {
        ret = PGP_ERROR_UNZIP;
    }


    free(m_unzip);
    free(m_plain);
    free(m_final);

    return ret;
}