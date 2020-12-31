#include "RC4.h"

INT RC4_init(BYTE* key, UINT key_length)
{
    BYTE R[256];
    UINT i, j;
    BYTE tmp;

    // init I, J
    S_I = S_J = 0;

    // init table S
    for (i = 0; i <= 255; i++)
    {
        S[i] = i;
    }

    // fill in table R
    for (i = 0; i <= 255; i++)
    {
        R[i] = key[i % key_length];
    }

    // shuffle table S
    for (i = 0, j = 0; i <= 255; i++)
    {
        // j = (j + S[i] + key[i % key_length]) % 256;
        j = (j + S[i] + R[i]) % 256;

        tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }

    return 0;
}

INT RC4(BYTE* in_text, BYTE* out_text, UINT text_length)
{
    // encrypt or decrypt
    UINT text_index, h;
    BYTE tmp, k;

    for (text_index = 0; text_index <= text_length - 1; text_index++)
    {
        // change state
        S_I = (S_I + 1) % 256;
        S_J = (S_J + S[S_I]) % 256;
        tmp = S[S_I];
        S[S_I] = S[S_J];
        S[S_J] = tmp;

        // generate key byte
        h = (S[S_I] + S[S_J]) % 256;
        k = S[h];

        out_text[text_index] = in_text[text_index] ^ k;
    }
    return 0;
}