#include <assert.h>
#include <stdio.h>
#include "../include/base64.h"
#include "../include/util.h"
#include "../include/sm.h"


extern Handles g_handles;


static PSM_KEY_ATTRIBUTE create_pubkey_attr(const char *start_date,
                                            const char *end_date) {
    PSM_KEY_ATTRIBUTE pubkey_attr =
        (PSM_KEY_ATTRIBUTE)malloc(sizeof(SM_KEY_ATTRIBUTE));
    PSM_ECC_PARAMETER ecc_param =
        (PSM_ECC_PARAMETER)malloc(sizeof(SM_ECC_PARAMETER));
    memset(pubkey_attr, 0, sizeof(SM_KEY_ATTRIBUTE));
    memset(ecc_param,   0, sizeof(SM_ECC_PARAMETER));

    char start_date_compress[DATE_LEN + 1] = {0};
    char end_date_compress[DATE_LEN + 1] = {0};
    int len =sizeof(start_date_compress);
    compress_date(start_date, start_date_compress, &len);
    len = sizeof(end_date_compress);
    compress_date(end_date, end_date_compress, &len);

    pubkey_attr->uiObjectClass  = SMO_PUBLIC_KEY;
    pubkey_attr->KeyType        = SM_KEY_ECC_PUBLIC;
    pubkey_attr->uiKeyLabel     = 1;
    memcpy(pubkey_attr->byStartDate,
           start_date_compress,
           sizeof(pubkey_attr->byStartDate));
    memcpy(pubkey_attr->byEndDate,
           end_date_compress,
           sizeof(pubkey_attr->byEndDate));

    pubkey_attr->pParameter     = ecc_param;
    pubkey_attr->uiParameterLen = sizeof(SM_ECC_PARAMETER);

    ecc_param->uiModulusBits     = SMMA_ECC_FP_256_MODULUS_BITS;
    pubkey_attr->uiFlags = SMKA_VERIFY |
                           SMKA_EXTRACTABLE |
                           SMKA_WRAP |
                           SMKA_UNWRAP;

    return pubkey_attr;
}


static PSM_KEY_ATTRIBUTE create_prikey_attr(const char *start_date,
                                            const char *end_date) {
    PSM_KEY_ATTRIBUTE prikey_attr =
        (PSM_KEY_ATTRIBUTE)malloc(sizeof(SM_KEY_ATTRIBUTE));
    PSM_ECC_PARAMETER ecc_param =
        (PSM_ECC_PARAMETER)malloc(sizeof(SM_ECC_PARAMETER));
    memset(prikey_attr, 0, sizeof(SM_KEY_ATTRIBUTE));
    memset(ecc_param,   0, sizeof(SM_ECC_PARAMETER));

    char start_date_compress[DATE_LEN + 1] = {0};
    char end_date_compress[DATE_LEN + 1] = {0};
    int len =sizeof(start_date_compress);
    compress_date(start_date, start_date_compress, &len);
    len = sizeof(end_date_compress);
    compress_date(end_date, end_date_compress, &len);

    prikey_attr->uiObjectClass  = SMO_PRIVATE_KEY;
    prikey_attr->KeyType        = SM_KEY_ECC_PRIVATE;
    prikey_attr->uiKeyLabel     = 1;
    memcpy(prikey_attr->byStartDate,
           start_date_compress,
           sizeof(prikey_attr->byStartDate));
    memcpy(prikey_attr->byEndDate,
           end_date_compress,
           sizeof(prikey_attr->byEndDate));

    prikey_attr->pParameter = ecc_param;
    prikey_attr->uiParameterLen = sizeof(SM_ECC_PARAMETER);

    ecc_param->uiModulusBits = SMMA_ECC_FP_256_MODULUS_BITS;
    prikey_attr->uiFlags =
        SMKA_SIGN | SMKA_EXTRACTABLE | SMKA_WRAP | SMKA_UNWRAP;

    return prikey_attr;
}


static void destroy_pubkey_attr(PSM_KEY_ATTRIBUTE pubkey_attr) {
    if (NULL != pubkey_attr) {
        if (NULL != pubkey_attr->pParameter) {
            free(pubkey_attr->pParameter);
            pubkey_attr->pParameter = NULL;
        }
        free(pubkey_attr);
        pubkey_attr = NULL;
    }
}


static void destroy_prikey_attr(PSM_KEY_ATTRIBUTE prikey_attr) {
    if (NULL != prikey_attr) {
        if (NULL != prikey_attr->pParameter) {
            free(prikey_attr->pParameter);
            prikey_attr->pParameter = NULL;
        }
        free(prikey_attr);
        prikey_attr = NULL;
    }
}


/* 1. generate key pair
 * 2. export key pair
 * 3. destroy key pair
 */
Result generate_ecc_key(const char *start_date,
                        const char *end_date,
                        char *hex_public,
                        int hex_public_len,
                        char *hex_private,
                        int hex_private_len) {
    /********************/
    if (MOCK_MODE) {
        strcpy(hex_public, "640e565c268e6ba9fdb61ea82f0eb0a405d41b3b35"
                           "682e5a497c064a21681133f984548ef27e784073e9"
                           "8fefa7f9873d1ce059f9e784667a3efe7155bfe6faa0");
        strcpy(hex_private, "570999c9973d33be5e52c0bf74307950"
                            "67ab7fb926f02ee0962ee5d3c61254f8");
        MOCK;
    }
    /********************/

    Result result = init_result();
    int ret = SM_ERR_FREE;

    SM_PIPE_HANDLE h_pipe = g_handles.h_pipe;
    SM_KEY_HANDLE h_auth_key = g_handles.h_auth_key;

    PSM_KEY_ATTRIBUTE pubkey_attr = create_pubkey_attr(start_date, end_date);
    PSM_KEY_ATTRIBUTE prikey_attr = create_prikey_attr(start_date, end_date);

    /* generate key pair */
    SM_KEY_HANDLE h_pubkey = NULL;
    SM_KEY_HANDLE h_prikey = NULL;
    ret = SM_GenerateKeyPair(h_pipe, pubkey_attr, &h_pubkey,
                             prikey_attr, &h_prikey);
    if ( ret != SM_ERR_FREE ) {
        result.code = ret;
        goto fail;
    }


    /* export key pair */
    char public_key[SMMA_ECC_FP_256_PUBLIC_KEY_LEN + 1] = {0};
    char private_key[SMMA_ECC_FP_256_PRIVATE_KEY_LEN + 1] = {0};
    int pubkey_len = 0, prikey_len = 0;
    SM_ALGORITHM algorithm;
    memset(&algorithm, 0, sizeof(SM_ALGORITHM));
    algorithm.AlgoType = SMM_ALG34_ECB;
    algorithm.pParameter = SM_NULL;
    algorithm.uiParameterLen = 0;

    ret = SM_ExportPublicKey(h_pipe, h_pubkey,
                             (PSM_BYTE)public_key,
                             (PSM_WORD)&pubkey_len);
    if (ret != SM_ERR_FREE) {
        result.code = ret;
        goto fail;
    }
    ret = SM_ExportPrivateKey(h_pipe, h_prikey, h_auth_key, &algorithm,
                              (PSM_BYTE)private_key, (PSM_WORD)&prikey_len);
    if (ret != SM_ERR_FREE) {
        result.code = ret;
        goto fail;
    }

    to_hex(hex_public, hex_public_len, public_key, pubkey_len);
    to_hex(hex_private, hex_private_len, private_key, prikey_len);


    /* destroy key pair */
    ret = SM_DestroyPublicKey(h_pipe, h_pubkey);
    result.code = (result.code == SM_ERR_FREE)? ret : result.code;
    ret = SM_DestroyPrivateKey(h_pipe, h_prikey);
    result.code = (result.code == SM_ERR_FREE)? ret : result.code;

    h_pubkey = NULL;
    h_prikey = NULL;
    destroy_prikey_attr(prikey_attr);
    destroy_pubkey_attr(pubkey_attr);

    return result;


fail:
    destroy_prikey_attr(prikey_attr);
    destroy_pubkey_attr(pubkey_attr);
    if (h_pubkey != NULL) SM_DestroyPublicKey(h_pipe, h_pubkey);
    if (h_prikey != NULL) SM_DestroyPrivateKey(h_pipe, h_prikey);
    return result;
}


Result sm3_hash_data(const char *data, int data_len,
                     char *digest, int *digest_len) {
    /********************/
    if (MOCK_MODE) {
        from_hex(digest, digest_len, "44f0061e69fa6fdfc290c494654a05dc"
                                     "0c053da7e5c52b84ef93a9d67d3fff88");
        MOCK;
    }
    /********************/

    Result result = init_result();
    int ret = SM_ERR_FREE;

    SM_PIPE_HANDLE h_pipe = g_handles.h_pipe;

    SM_ALGORITHM hash_algorithm;
    memset(&hash_algorithm, 0, sizeof(SM_ALGORITHM));
    hash_algorithm.AlgoType = SMM_SCH_256;
    hash_algorithm.pParameter = SM_NULL;
    hash_algorithm.uiParameterLen = SMMA_SCH_256_LEN;

    ret = SM_Digest(h_pipe, NULL, &hash_algorithm, (PSM_BYTE)data,
                   (SM_UINT)data_len, (PSM_BYTE)digest, (PSM_UINT)digest_len);
    result.code = ret;
    return result;
}


/* 1. hash data
 * 2. verify
 */
Result sm2_verify(const char *hex_public,
                  const char *plain_data,
                  int plain_data_len,
                  const char *signature,
                  int signature_len,
                  int *verify_result) {
    /********************/
    if (MOCK_MODE) {
        *verify_result = 0;
        MOCK;
    }
    /********************/

    SM_PIPE_HANDLE h_pipe = g_handles.h_pipe;

    Result result = init_result();
    int ret = SM_ERR_FREE;
    char digest[MAX_DIGEST_LEN + 1] = {0};
    int digest_len = 0;
    char public_key[SMMA_ECC_FP_256_PUBLIC_KEY_LEN + 1] = {0};
    int pubkey_len = 0;
    SM_BLOB_KEY public_blob;
    memset(&public_blob, 0, sizeof(SM_BLOB_KEY));

    from_hex(public_key, &pubkey_len,  hex_public);
    public_blob.pbyData = (PSM_BYTE)public_key;
    public_blob.uiDataLen = (SM_UINT)pubkey_len;


    /* hash data */
    result = sm3_hash_data(plain_data, plain_data_len, digest, &digest_len);
    if (result.code != YERR_SUCCESS) return result;


    /* verify data */
    SM_ALGORITHM verify_algorithm;
    memset(&verify_algorithm, 0, sizeof(SM_ALGORITHM));
    verify_algorithm.AlgoType = SMM_ECC_FP_VERIFY;
    verify_algorithm.pParameter = SM_NULL;
    verify_algorithm.uiParameterLen = 0;
    verify_algorithm.uiReserve = SMMA_ECC_FP_256_MODULUS_BITS;

    ret = SM_ECCVerify(h_pipe, &public_blob, &verify_algorithm,
                       (PSM_BYTE)digest, (SM_UINT)digest_len,
                       (PSM_BYTE)signature, (SM_UINT)signature_len);

    *verify_result = UNIFY_ERROR_CODE(ret);
    return result;
}


/* 1. hash data
 * 2. import key
 * 3. sign
 * 4. destroy key
 */
Result sm2_sign(const char *hex_private,
                const char *plain_data,
                int plain_data_len,
                char *signature,
                int *signature_len) {
    /********************/
    if (MOCK_MODE) {
        from_hex(signature, signature_len, "1c454af499e502206b6fba2dc2f5eb055a2"
                                           "6f1dde077cfe5f71e6bb5de3fdc64bf177d"
                                           "d635ac076fef1bf1838591233806bc14d02"
                                           "186576d8e2dbef4d0b14e2f");
        MOCK;
    }
    /********************/

    SM_PIPE_HANDLE h_pipe = g_handles.h_pipe;
    SM_KEY_HANDLE h_auth_key = g_handles.h_auth_key;

    Result result = init_result();
    int ret = SM_ERR_FREE;
    char digest[MAX_DIGEST_LEN + 1] = {0};
    int digest_len = 0;
    char private_key[SMMA_ECC_FP_256_PRIVATE_KEY_LEN + 1] = {0};
    int prikey_len = 0;
    from_hex(private_key, &prikey_len, hex_private);
    SM_KEY_HANDLE h_prikey = NULL;


    /* hash data */
    result = sm3_hash_data(plain_data, plain_data_len, digest, &digest_len);
    if (result.code != YERR_SUCCESS) return result;


    /* import key */
    char date[DATE_LEN + 1] = {0};
    date_today(date, sizeof(date));
    PSM_KEY_ATTRIBUTE prikey_attr = create_prikey_attr(date, "20991231");
    SM_ALGORITHM algorithm;
    memset(&algorithm, 0, sizeof(SM_ALGORITHM));
    algorithm.AlgoType = SMM_ALG34_ECB;
    algorithm.pParameter = SM_NULL;
    algorithm.uiParameterLen = 0;
    ret = SM_ImportPrivateKey(h_pipe, (PSM_BYTE)private_key, prikey_len,
                              h_auth_key, &algorithm, prikey_attr, &h_prikey);
    if ( ret != SM_ERR_FREE ) {
        result.code = ret;
        return result;
    }


    /* sign data */
    SM_ALGORITHM sign_algorithm;
    memset(&sign_algorithm, 0, sizeof(SM_ALGORITHM));
    sign_algorithm.AlgoType = SMM_ECC_FP_SIGN;
    sign_algorithm.pParameter = SM_NULL;
    sign_algorithm.uiParameterLen = 0;
    sign_algorithm.uiReserve = SMMA_ECC_FP_256_MODULUS_BITS;

    SM_BLOB_KEY private_blob;
    memset(&private_blob, 0, sizeof(SM_BLOB_KEY));

    private_blob.pbyData = (SM_BYTE*)&h_prikey;
    private_blob.uiDataLen = sizeof(SM_KEY_HANDLE);

    ret = SM_ECCSignature(h_pipe, &private_blob, &sign_algorithm,
                          (PSM_BYTE)digest, (SM_UINT)digest_len,
                          (PSM_BYTE)signature, (PSM_UINT)signature_len);
    if ( ret != SM_ERR_FREE ) {
        result.code = ret;
        goto fail;
    }


    /* destroy key */
    ret = SM_DestroyPrivateKey(h_pipe, h_prikey);
    result.code = ret;
    return result;


fail:
    if (NULL != h_prikey) SM_DestroyPrivateKey(h_pipe, h_prikey);
    return result;
}
