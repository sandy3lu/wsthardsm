/*!
 *  Copyright (C), 2001-2011, SCW.
 *  \file       sm_inn_type.h
 *  \author     WorkGroup
 *  \version    V5.2.1108.2415
 *  \date       2011-08-24
 *  \note       define some macro, data type by api5.2.
 *
 *  History:
 *
 *  [OS macro]
 *  WIN32       windows 32
 *  WIN64       windows 64, only vc2005
 *  __linux__   linux
 *
 *  #if _MSC_VER < 1300
 *  #error Compiler version not supported by Windows 64
 *  #endif
 *
 *  [linux macro]
 *  __KERNEL__  driver define
 *  MODULE      driver define
 *  __SMP__     multi-core
 *  -fPIC       directs the compiler to generate position independent code
 *              64bits system need, in CFLAGS
 */

#ifndef _SM_INN_TYPE_H_
#define _SM_INN_TYPE_H_

#include "sm_api_type.h"

#ifdef WIN32
    typedef CRITICAL_SECTION        SM_CRITICAL;
    typedef OVERLAPPED              SM_OVERLAPPED;

    typedef void *                  SM_DEVHANDLE;
    typedef SM_HANDLE               SM_EVENTHANDLE;
    typedef SM_HANDLE               SM_THREADHANDLE;
    typedef unsigned                SM_THREADFUNRET;
    typedef unsigned (__stdcall *SM_PTHREADFUN)( PSM_VOID );

#elif  WIN64
    typedef CRITICAL_SECTION        SM_CRITICAL;
    typedef OVERLAPPED              SM_OVERLAPPED;

    typedef void *                  SM_DEVHANDLE;
    typedef SM_HANDLE               SM_EVENTHANDLE;
    typedef SM_HANDLE               SM_THREADHANDLE;
    typedef unsigned                SM_THREADFUNRET;
    typedef unsigned (__stdcall *SM_PTHREADFUN)( PSM_VOID );

#elif   __linux__
    typedef pthread_rwlock_t        SM_CRITICAL;
    union semun {
        SM_INT              val;
        struct semid_ds*    buf;
        SM_WORD*            array;
        struct seminfo*     __buf; };

    typedef SM_INT                  SM_DEVHANDLE;
    typedef PSM_VOID                SM_OVERLAPPED;

    typedef SM_HANDLE               SM_EVENTHANDLE;
    typedef pthread_t               SM_THREADHANDLE;
    typedef PSM_VOID                SM_THREADFUNRET;
    typedef PSM_VOID (*SM_PTHREADFUN)( PSM_VOID );

    #ifdef CONFIG_SMP
        #define LOCK                "lock ;"
    #else
        #define LOCK                ""
    #endif

#endif

#ifndef MAX_PATH
#define MAX_PATH                 260
#endif

#define SMMA_ECC_PC              0x04
#define SMMA_ECC_PC_LEN          1

/* ///////////////////////////////////////////////////////////////////////// */
/* define Algorithm */
/* ///////////////////////////////////////////////////////////////////////// */
#define SMMA_ALG_CTX_LEN                1024

/* RSA */
#define SMM_RSA                             0x00000101

/* ECC_FP */
#define SMM_ECC_FP_ENC                      0x00000111
#define SMM_ECC_FP_DEC                      0x00000112
#define SMM_ECC_FP_SIGN                     0x00000113
#define SMM_ECC_FP_VERIFY                   0x00000114

/* ///////////////////////////////////////////////////////////////////////// */
/* define Key type */
/* ///////////////////////////////////////////////////////////////////////// */

/* RSA */
#define SMK_RSA                             0x00000001
#define SMK_RSA_PUBLIC                      0x00000002
#define SMK_RSA_PRIVATE                     0x00000003

/* ECC_FP */
#define SMK_ECC_FP_PUBLIC                   0x00000005
#define SMK_ECC_FP_PRIVATE                  0x00000006

/* ///////////////////////////////////////////////////////////////////////// */
/* Algorithm character */
/* ///////////////////////////////////////////////////////////////////////// */
/* RSA_1024 */
#define SMMA_RSA_1024_MODULUS_BITS          1024
#define SMMA_RSA_1024_BLOCK_LEN             ((SMMA_RSA_1024_MODULUS_BITS + 7) / 8)/* 128 */

#define SMMA_RSA_1024_PUBLIC_KEY_LEN        260
#define SMMA_RSA_1024_PRIVATE_KEY_LEN       708

#define SMMA_RSA_1024_MAX_BITS                1024
#define SMMA_RSA_1024_MAX_LEN                 ((SMMA_RSA_1024_MAX_BITS+7)/8)
#define SMMA_RSA_1024_MAX_PBITS               (SMMA_RSA_1024_MAX_BITS+1)/2
#define SMMA_RSA_1024_MAX_PLEN                ((SMMA_RSA_1024_MAX_PBITS+7)/8)

/*! struct SM_RSA_PARAMETER. */
typedef struct _SM_RSA_PARAMETER
{
/*!
* A member variable.
* The modulus bit of Rsa
    */
    SM_UINT         uiModulusBits;
    /*!
    * A member variable.
    * The parameter of Rsa
    */
    PSM_VOID        pParameter;
    /*!
    * A member variable.
    * The parameter length of Rsa
    */
    SM_UINT          uiParameterLen;
} SM_RSA_PARAMETER, *PSM_RSA_PARAMETER;

typedef struct _SM_RSA_1024_PUBKEY
{
    SM_UINT bits;
    SM_BYTE m[SMMA_RSA_1024_MAX_LEN];
    SM_BYTE e[SMMA_RSA_1024_MAX_LEN];
} SM_RSA_1024_PUBKEY, *PSM_RSA_1024_PUBKEY;

typedef struct _SM_RSA_1024_PRVKEY
{
    SM_UINT bits;
    SM_BYTE m[SMMA_RSA_1024_MAX_LEN];
    SM_BYTE e[SMMA_RSA_1024_MAX_LEN];
    SM_BYTE d[SMMA_RSA_1024_MAX_LEN];
    SM_BYTE prime[2][SMMA_RSA_1024_MAX_PLEN];  /* p & q */
    SM_BYTE pexp[2][SMMA_RSA_1024_MAX_PLEN];   /* dmp1 & dmq1 */
    SM_BYTE coef[SMMA_RSA_1024_MAX_PLEN];      /* iqmp */
} SM_RSA_1024_PRVKEY, *PSM_RSA_1024_PRVKEY;

typedef struct _ST_ECC_256_COORDINATE
{
    unsigned char byX1[32];
    unsigned char byY1[32];
    unsigned char byX2[32];
    unsigned char byY2[32];
} ST_ECC_256_COORDINATE, *PST_ECC_256_COORDINATE;

/* ECC_FP_192 */
#define SMMA_ECC_FP_192_MODULUS_BITS        192
#define SMMA_ECC_FP_192_BLOCK_LEN           \
                                ((SMMA_ECC_FP_192_MODULUS_BITS + 7) / 8)/* 24 */
#define SMMA_ECC_FP_192_ENC_MIN_LEN         1
#define SMMA_ECC_FP_192_ENC_MAX_LEN         1024
#define SMMA_ECC_FP_192_SIG_MIN_LEN         SMMA_ECC_FP_192_BLOCK_LEN
#define SMMA_ECC_FP_192_SIG_MAX_LEN         SMMA_ECC_FP_192_BLOCK_LEN
#define SMMA_ECC_FP_192_SIG_VALLEN          (SMMA_ECC_FP_192_BLOCK_LEN * 2)

#define SMMA_ECC_FP_192_CHECKVAL_LEN        192

#define SMMA_ECC_FP_192_PUBLIC_KEY_LEN      (4 + SMMA_ECC_FP_192_BLOCK_LEN * 2)
#define SMMA_ECC_FP_192_PRIVATE_KEY_LEN     (4 + SMMA_ECC_FP_192_BLOCK_LEN)

#define SMMA_ECC_FP_256_CHECKVAL_LEN        SMMA_SCH_256_LEN

#endif
