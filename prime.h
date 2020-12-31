/*****************************************************************************
Filename: prime.h
Author  : Chuck Li (lch0821@foxmail.com)
Date    : 2018-01-19 17:57:27
Description:
*****************************************************************************/
#ifndef __PRIME_H__
#define __PRIME_H__

#include <stdint.h>

#include "bignum.h"

void initialize_rand(void);
void generate_rand(uint8_t *block, uint32_t block_len);
int generate_prime(bn_t *a, bn_t *lower, bn_t *upper, bn_t *d, uint32_t digits);

#endif  // __PRIME_H__
