/* IDEA(International Data Encryption Algorithm), refer to http://www.quadibloc.com/crypto/co040302.htm
 * IDEA.c, an IDEA encryption and decryption program.
 * Author shenyang
 * Mar. 4th, 2011
 * TODO: Fault analysis on IDEA, defence of fault analysis on IDEA.
 */

#ifndef IDEA_H  
#include "IDEA.h"  
#endif  

#include <string.h>  
#include <stdio.h>  
#include <stdlib.h>

 /* define operation */
static uint16_t add_mod(uint16_t a, uint16_t b);
static uint16_t mp_mod(uint16_t a, uint16_t b);
static uint16_t XOR(uint16_t a, uint16_t b);
static status_t left_shift(uint16_t key[8], int num);
static void swap(uint16_t* a, uint16_t* b);

/* addition and mod 65536 */
static uint16_t add_mod(uint16_t a, uint16_t b)
{
    uint32_t tmp = a + b;
    uint16_t ret = tmp % IDEA_ADD_MODULAR;
    return ret;
}

/* multiply and mod 65537 */
static uint16_t mp_mod(uint16_t a, uint16_t b)
{
    /* Note: In IDEA, for purposes of multiplication, a 16 bit word containing all zeroes is considered to represent the number 65,536;
     * other numbers are represented in conventional unsigned notation, and multiplication is modulo the prime number 65,537
     */
    uint64_t tmp, tmp_a, tmp_b; //if both a and b are 2^16, the result will be 2^32 which will exceed a 32-bit int  
    tmp_a = a == 0 ? (1 << 16) : a;
    tmp_b = b == 0 ? (1 << 16) : b;
    tmp = (tmp_a * tmp_b) % IDEA_MP_MODULAR;
    tmp = tmp == (1 << 16) ? 0 : tmp;
    return (uint16_t)(tmp);
}

/* XOR */
static uint16_t XOR(uint16_t a, uint16_t b)
{
    return a ^ b;
}

static void swap(uint16_t* a, uint16_t* b)
{
    uint16_t c = 0;
    c = *a;
    *a = *b;
    *b = c;
}

/* IDEA encryption */
status_t idea_encrypt(uint64_t plaintext, uint16_t key[8], uint64_t* ciphertext)
{
    uint16_t X[4], sub_key[52], out[4];
    status_t st;
    int i, j;

    /* cut 64-bit plaintext into 4 16-bit sub blocks */
    for (i = 0; i < 4; i++)
        X[i] = (plaintext >> (48 - i * 16)) & 0xffff;

    /* generate sub keys */
    st = subkey_generation(key, sub_key);

    for (i = 0; i < 8; i++)
    {
        idea_round(X, &(sub_key[i * 6]), out);
        for (j = 0; j < 4; j++)
            X[j] = out[j];
    }

    /* round 9, do output transform */
    //Note that the swap of B and C is not performed after round 8. So we swap them again.  
    swap(&(out[1]), &(out[2]));
    out[0] = mp_mod(out[0], sub_key[48]);
    out[1] = add_mod(out[1], sub_key[49]);
    out[2] = add_mod(out[2], sub_key[50]);
    out[3] = mp_mod(out[3], sub_key[51]);
    *ciphertext = out[0];
    for (i = 1; i <= 3; i++)
        *ciphertext = ((*ciphertext) << 16) | out[i];

    return st;
}

/* IDEA decryption */
status_t idea_decrypt(uint64_t ciphertext, uint16_t key[8], uint64_t* plaintext)
{
    status_t st;
    uint16_t X[4], sub_dkey[52], out[4];
    int i, j;

    for (i = 0; i < 4; i++)
        X[i] = (ciphertext >> (48 - i * 16)) & 0xffff;

    /* generate sub keys for decryption*/
    st = subdkey_generation(key, sub_dkey);
    if (st != IDEA_SUCCESS)
        return st;

    for (i = 0; i < 8; i++)
    {
        idea_round(X, &(sub_dkey[i * 6]), out);
        for (j = 0; j < 4; j++)
            X[j] = out[j];
    }

    out[0] = mp_mod(out[0], sub_dkey[48]);
    out[1] = add_mod(out[1], sub_dkey[49]);
    out[2] = add_mod(out[2], sub_dkey[50]);
    out[3] = mp_mod(out[3], sub_dkey[51]);
    swap(&(out[1]), &(out[2]));     //Note that the unswap in decryption is called after transform, that is different from the encryption.  

    *plaintext = out[0];
    for (i = 1; i <= 3; i++)
        *plaintext = ((*plaintext) << 16) | out[i];

    return st;
}

status_t idea_round(uint16_t X[4], uint16_t Z[6], uint16_t out[4])
{
    status_t st;
    uint16_t tmp[4], ma_in[2], ma_out[2];
    tmp[0] = mp_mod(X[0], Z[0]);    //step 1. multiply X1 by 1st sub key  
    tmp[1] = add_mod(X[1], Z[1]);   //step 2. add X2 to 2nd sub key  
    tmp[2] = add_mod(X[2], Z[2]);   //step 3. add X3 to 3rd sub key  
    tmp[3] = mp_mod(X[3], Z[3]);    //step 4. multiply X4 by 4th sub key  

    ma_in[0] = XOR(tmp[0], tmp[2]); //step 5. XOR results in step 1 and step 3  
    ma_in[1] = XOR(tmp[1], tmp[3]); //step 6. XOR results in step 2 and step 4  

    st = MA(ma_in, &Z[4], ma_out);  //step 7. MA diffusion  

    /* step 8. generate the output*/
    out[0] = XOR(tmp[0], ma_out[1]); // 1
    out[1] = XOR(tmp[1], ma_out[0]);
    out[2] = XOR(tmp[2], ma_out[1]);
    out[3] = XOR(tmp[3], ma_out[0]);
    swap(&(out[1]), &(out[2]));

    return st;
}

/* MA diffusion */
status_t MA(uint16_t ma_in[2], uint16_t sub_key[2], uint16_t ma_out[2])
{
    uint16_t tmp[2];

    tmp[0] = mp_mod(ma_in[0], sub_key[0]);
    tmp[1] = add_mod(ma_in[1], tmp[0]);
    ma_out[1] = mp_mod(tmp[1], sub_key[1]);
    ma_out[0] = add_mod(tmp[0], ma_out[1]);

    return IDEA_SUCCESS;
}

/* sub keys generation */
status_t subkey_generation(uint16_t key[8], uint16_t sub_key[52])
{
    int i, j;
    uint16_t tmp_key[8];
    for (i = 0; i < 8; i++)
        tmp_key[i] = key[i];
    for (i = 0; i < 6; i++)
    {
        for (j = 0; j < 8; j++)
            sub_key[i * 8 + j] = tmp_key[j];
        left_shift(tmp_key, 25);
    }
    for (i = 0; i < 4; i++)
        sub_key[48 + i] = tmp_key[i];
    return IDEA_SUCCESS;
}

/* sub dkeys generation
 *
 *The decryption key schedule is:
 *
 *The first four subkeys for decryption are:
 *
 *KD(1) = 1/K(49)
 *KD(2) =  -K(50)
 *KD(3) =  -K(51)
 *KD(4) = 1/K(52)
 *
 *and they do not quite follow the same pattern as the remaining subkeys which follow.
 *
 *The following is repeated eight times, adding 6 to every decryption key's index and subtracting 6 from every encryption key's index:
 *
 *KD(5)  =   K(47)
 *KD(6)  =   K(48)
 *
 *KD(7)  = 1/K(43)
 *KD(8)  =  -K(45)
 *KD(9)  =  -K(44)
 *KD(10) = 1/K(46)
 *
 */
status_t subdkey_generation(uint16_t key[8], uint16_t sub_dkey[52])
{
    status_t st;
    int i;
    uint16_t sub_key[52];
    uint32_t tmp;

    st = subkey_generation(key, sub_key);

    st = extended_eucild(sub_key[48], IDEA_MP_MODULAR, &tmp);
    if (st != IDEA_SUCCESS)
    {
        printf("subdkey_generation error!/n");
        return st;
    }
    sub_dkey[0] = tmp == 65536 ? 0 : (uint16_t)tmp;
    sub_dkey[1] = (IDEA_ADD_MODULAR - sub_key[49]) % IDEA_ADD_MODULAR;
    sub_dkey[2] = (IDEA_ADD_MODULAR - sub_key[50]) % IDEA_ADD_MODULAR;
    st = extended_eucild(sub_key[51], IDEA_MP_MODULAR, &tmp);
    if (st != IDEA_SUCCESS)
    {
        printf("subdkey_generation error!/n");
        return st;
    }
    sub_dkey[3] = tmp == 65536 ? 0 : (uint16_t)tmp;

    for (i = 0; i < 8; i++)   //This is awful?!...May be I should make a table.  
    {
        sub_dkey[4 + i * 6] = sub_key[52 - (i + 1) * 6];
        sub_dkey[4 + i * 6 + 1] = sub_key[52 - (i + 1) * 6 + 1];
        st = extended_eucild(sub_key[52 - (i + 1) * 6 - 4], IDEA_MP_MODULAR, &tmp);
        if (st != IDEA_SUCCESS)
        {
            printf("subdkey_generation error!/n");
            return st;
        }
        sub_dkey[4 + i * 6 + 2] = tmp == 65536 ? 0 : (uint16_t)tmp;
        sub_dkey[4 + i * 6 + 3] = (IDEA_ADD_MODULAR - sub_key[52 - (i + 1) * 6 - 2]) % IDEA_ADD_MODULAR;
        sub_dkey[4 + i * 6 + 4] = (IDEA_ADD_MODULAR - sub_key[52 - (i + 1) * 6 - 3]) % IDEA_ADD_MODULAR;
        st = extended_eucild(sub_key[52 - (i + 1) * 6 - 1], IDEA_MP_MODULAR, &tmp);
        if (st != IDEA_SUCCESS)
        {
            printf("subdkey_generation error!/n");
            return st;
        }
        sub_dkey[4 + i * 6 + 5] = tmp == 65536 ? 0 : (uint16_t)tmp;
    }
    return IDEA_SUCCESS;
}

/* left shift */
static status_t left_shift(uint16_t key[8], int num)
{
    uint16_t copy_key[8];
    int i;
    for (i = 0; i < 8; i++)
        copy_key[i] = key[i];
    for (i = 0; i < 8; i++)
        key[i] = (copy_key[(i + num / 16) % 8] << (num % 16)) | (copy_key[(i + num / 16 + 1) % 8] >> (16 - num % 16));
    return IDEA_SUCCESS;
}

/* Extended Eucild Algorithm to caculate d^-1 mod k*/
status_t extended_eucild(uint16_t d, uint32_t k, uint32_t* result)
{
    int x[4], y[4], t[4], q;
    int i;
    x[1] = x[2] = 0;
    x[3] = k;
    y[1] = 0, y[2] = 1;
    y[3] = d == 0 ? (1 << 16) : d;

    while (y[3] > 1)
    {
        q = x[3] / y[3];
        for (i = 1; i <= 3; i++)
            t[i] = x[i] - q * y[i];
        for (i = 1; i <= 3; i++)
            x[i] = y[i];
        for (i = 1; i <= 3; i++)
            y[i] = t[i];
    }
    if (y[3] == 1)
    {
        if (y[2] < 0)
            y[2] += k;
        *result = y[2];
        return IDEA_SUCCESS;
    }
    else
        return IDEA_ERROR;
}

status_t idea_encrypt_all(uint8_t* plain, uint32_t plain_len, uint8_t* key, uint8_t* cipher, uint32_t* cipher_len)
{
    // padding
    // plain || 0xFF || 0x00...0x00
    uint32_t i;
    uint32_t padding_len = 8 - (plain_len % 8);
    uint32_t padded_len = plain_len + padding_len;
    uint8_t* padded_plain = (uint8_t*)calloc((uint64_t)padded_len, 1);

    // padding
    memcpy(padded_plain, plain, plain_len);
    padded_plain[plain_len] = 0xff;
    for (i = plain_len + 1; i < padded_len; i++)
    {
        padded_plain[i] = 0x00;
    }

    /*for (i = 0, *cipher_len = 0; i < plain_len; i += 8, *cipher_len += 8)
    {
        idea_encrypt((uint64_t)(plain[i]), (uint16_t*)key, (uint64_t*)(cipher + *cipher_len));
    }*/
    // start encrypt
    for (i = 0, *cipher_len = 0; i < padded_len; i += 8, *cipher_len += 8)
    {
        idea_encrypt(*(uint64_t*)(padded_plain + i), (uint16_t*)key, (uint64_t*)(cipher + *cipher_len));
    }

    return 0;
}
status_t idea_decrypt_all(uint8_t* cipher, uint32_t cipher_len, uint8_t* key, uint8_t* plain, uint32_t* plain_len)
{
    // decrypt
    uint32_t i;
    for (i = 0, *plain_len = 0; i < cipher_len; i += 8, *plain_len += 8)
    {
        idea_decrypt(*(uint64_t*)(cipher+i), (uint16_t*)key, (uint64_t*)(plain + *plain_len));
    }

    // unpadding
    while (plain[*plain_len - 1] != 0xff)
    {
        (*plain_len)--;
    }
    (*plain_len)--;

    return 0;
}