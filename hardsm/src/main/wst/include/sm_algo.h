/*!
 *  Copyright (C), 2001-2011, CETC30 SCW.
 *  \file       sm_algo.h
 *  \author     Chen-Daoyuan
 *  \version    V5.2.1106.2916
 *  \date       2011-06-29
 *  \note       define some algorithm macro by api5.2.
 *
 *  History:
 *  1. 2011-06-29:  created by Chen-Daoyuan
 *  2. 2011-09-19:  modified by Chen-Daoyuan
 */

#ifndef _SM_ALGO_H_
#define _SM_ALGO_H_

/* ///////////////////////////////////////////////////////////////////////// */
/* define Algorithm */
/* ///////////////////////////////////////////////////////////////////////// */
/* SM1 */
#define SMM_ALG34_ECB                   0x00000601
#define SMM_ALG34_CBC                   0x00000602
#define SMM_ALG34_MAC                   0x00000604

/* SM2 */
#define SMM_ECC_FP_ENC                  0x00000111
#define SMM_ECC_FP_DEC                  0x00000112
#define SMM_ECC_FP_SIGN                 0x00000113
#define SMM_ECC_FP_VERIFY               0x00000114
#define SMM_ECC_FP_EXCHANGE_KEY         0x00000115

/* SM3 */
#define SMM_SCH_256                     0x0000016C

/* SM4 */
#define SMM_ALG35_ECB                   0x00003a01
#define SMM_ALG35_CBC                   0x00003a02
#define SMM_ALG35_MAC                   0x00003a04

/* ///////////////////////////////////////////////////////////////////////// */
/* define Key type */
/* ///////////////////////////////////////////////////////////////////////// */
#define SM_KEY_ALG34_H          0x00000028      /* Key length 32bytes */
#define SM_KEY_ALG34_M          0x00000029      /* Key length 24bytes */
#define SM_KEY_ALG34_L          0x0000002a      /* Key length 16bytes */

#define SM_KEY_ALG35            0x00000109      /* Key length 16bytes */

#define SM_KEY_ECC_PUBLIC       0x00000005
#define SM_KEY_ECC_PRIVATE      0x00000006

/* ///////////////////////////////////////////////////////////////////////// */
/* Algorithm character */
/* ///////////////////////////////////////////////////////////////////////// */
/* SM1 */
#define SMMA_ALG34_BLOCK_LEN            16
#define SMMA_ALG34_KEY_L_LEN            SMMA_ALG34_BLOCK_LEN
#define SMMA_ALG34_IV_LEN               SMMA_ALG34_BLOCK_LEN
#define SMMA_ALG34_MAC_VALUE_LEN        16


/* SM2 */
#define SMMA_ECC_FP_256_MODULUS_BITS    256
#define SMMA_ECC_FP_256_BLOCK_LEN       ((SMMA_ECC_FP_256_MODULUS_BITS + 7) / 8)
#define SMMA_ECC_FP_256_ENC_MIN_LEN     1
#define SMMA_ECC_FP_256_ENC_MAX_LEN     128
#define SMMA_ECC_FP_256_SIG_MIN_LEN     SMMA_SCH_256_LEN
#define SMMA_ECC_FP_256_SIG_MAX_LEN     SMMA_SCH_256_LEN
#define SMMA_ECC_FP_256_SIG_VALLEN      (SMMA_ECC_FP_256_BLOCK_LEN * 2)
#define SMMA_ECC_FP_256_VER_VALLEN      (SMMA_ECC_FP_256_BLOCK_LEN * 2)
#define SMMA_ECC_FP_256_PUBLIC_KEY_LEN  (SMMA_ECC_FP_256_BLOCK_LEN * 2)
#define SMMA_ECC_FP_256_PRIVATE_KEY_LEN SMMA_ECC_FP_256_BLOCK_LEN
#define SMMA_ECC_FP_256_EXCHANGE_OUTLEN    4000

/* SM3 */
#define SMMA_SCH_256_LEN                32
#define SMMA_SCH_CBLOCK                 64

/* SM4 */
#define SMMA_ALG35_BLOCK_LEN            16
#define SMMA_ALG35_KEY_LEN              SMMA_ALG35_BLOCK_LEN
#define SMMA_ALG35_IV_LEN               SMMA_ALG35_BLOCK_LEN
#define SMMA_ALG35_MAC_VALUE_LEN        16

#endif
