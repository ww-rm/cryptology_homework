#pragma once
#ifndef AESWITHPUREC_AES_UTIL_H
#define AESWITHPUREC_AES_UTIL_H

#define MAX_LEN (2*1024*1024)
#define AES_KEY_SIZE 128

unsigned char* encrypt(const unsigned char* in, int in_len, unsigned int* out_len,
    const unsigned char* key, const unsigned char* iv);

unsigned char* decrypt(const unsigned char* in, int in_len, unsigned int* out_len,
    const unsigned char* key, const unsigned char* iv);

#endif //AESWITHPUREC_AES_UTIL_H