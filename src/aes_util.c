#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "aes_util.h"

unsigned char*
encrypt(const unsigned char* data, int in_len, unsigned int* out_len,
    const unsigned char* key, const unsigned char* iv) {
    if (in_len <= 0 || in_len >= MAX_LEN) {
        return NULL;
    }

    if (!data) {
        return NULL;
    }

    unsigned int rest_len = in_len % AES_BLOCK_SIZE;
    unsigned int padding_len = AES_BLOCK_SIZE - rest_len;
    unsigned int src_len = in_len + padding_len;

    unsigned char* input = (unsigned char*)calloc(1, src_len);
    memcpy(input, data, in_len);
    if (padding_len > 0) {
        //        memset(input + in_len, (unsigned char) padding_len, padding_len);
        for (unsigned int i = 0; i < padding_len; i++) {
            *(input + in_len + i) = (unsigned char)padding_len;
        }
    }

    unsigned char* buff = (unsigned char*)calloc(1, src_len);
    if (!buff) {
        free(input);
        return NULL;
    }

    unsigned int key_schedule[AES_BLOCK_SIZE * 4] = { 0 };

    aes_key_setup(key, key_schedule, AES_KEY_SIZE);
    aes_encrypt_cbc(input, src_len, buff, key_schedule, AES_KEY_SIZE, iv);
    *out_len = src_len;

    //内存释放
    free(input);

    return buff;
}

unsigned char
* decrypt(const unsigned char* data, int in_len, unsigned int* out_len,
    const unsigned char* key, const unsigned char* iv) {
    if (in_len <= 0 || in_len >= MAX_LEN) {
        return NULL;
    }
    if (!data) {
        return NULL;
    }

    unsigned int padding_len = 0;
    unsigned int src_len = in_len + padding_len;

    unsigned char* input = (unsigned char*)calloc(1, src_len);
    memcpy(input, data, in_len);
    if (padding_len > 0) {
        //        memset(input + in_len, (unsigned char) padding_len, padding_len);
        for (unsigned int i = 0; i < padding_len; i++) {
            *(input + in_len + i) = (unsigned char)padding_len;
        }
    }

    unsigned char* buff = (unsigned char*)calloc(1, src_len);
    if (!buff) {
        free(input);
        return NULL;
    }

    unsigned int key_schedule[AES_BLOCK_SIZE * 4] = { 0 };

    aes_key_setup(key, key_schedule, AES_KEY_SIZE);
    aes_decrypt_cbc(input, src_len, buff, key_schedule, AES_KEY_SIZE, iv);

    unsigned char* ptr = buff;
    ptr += (src_len - 1);
    padding_len = (unsigned int)*ptr;
    if (padding_len > 0 && padding_len <= AES_BLOCK_SIZE) {
        src_len -= padding_len;
    }

    *out_len = src_len;

    //内存释放
    free(input);

    return buff;
}