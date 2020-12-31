#pragma once
/* IDEA.h */
#ifndef IDEA_H  
#define IDEA_H  

/* define return status */
#define IDEA_SUCCESS        0  
#define IDEA_ERROR          1  

/* define data length */
#define IDEA_KEY_LEN        128  
#define IDEA_BLOCK_SIZE     64  
#define IDEA_SUB_BLOCK_SIZE 16  

/* define global variable */
#define IDEA_ADD_MODULAR    65536  
#define IDEA_MP_MODULAR     65537  

/* define operation mode */
#define ECB 0  
#define CBC 1  
#define CFB 2  
#define OFB 3  

/* define data type */
//typedef bool            bit_t, status_t;  
typedef unsigned char   byte_t, uint8_t;
typedef unsigned short  word_t, uint16_t;
typedef unsigned int    dword_t, uint32_t, status_t;
typedef unsigned long long uint64_t;

/* declare fuction */
status_t idea_encrypt(uint64_t plaintext, uint16_t key[8], uint64_t* ciphertext);
status_t idea_decrypt(uint64_t ciphertext, uint16_t key[8], uint64_t* plaintext);
status_t idea_round(uint16_t X[4], uint16_t Z[6], uint16_t out[4]);
status_t MA(uint16_t ma_in[2], uint16_t sub_key[2], uint16_t ma_out[2]);
status_t subkey_generation(uint16_t key[8], uint16_t sub_key[52]);
status_t subdkey_generation(uint16_t key[8], uint16_t sub_dkey[52]);
status_t extended_eucild(uint16_t d, uint32_t k, uint32_t* result);
status_t idea_encrypt_all(uint8_t* plain, uint32_t plain_len, uint8_t* key, uint8_t* cipher, uint32_t* cipher_len);
status_t idea_decrypt_all(uint8_t* cipher, uint32_t cipher_len, uint8_t* key, uint8_t* plain, uint32_t* plain_len);

#endif  