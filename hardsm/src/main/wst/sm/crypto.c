#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "../include/sm_api.h"
#include "../include/util.h"
#include "../include/key.h"
#include "../include/crypto.h"

#define MAX_ECC_ENCRYPT_LEN   1024

static SM_BYTE g_byiv[SMMA_ALG34_IV_LEN];
static SM_ALGORITHM g_hash_algorithm;
static SM_ALGORITHM g_mac_algorithm;
static SM_ALGORITHM g_sign_algorithm;
static SM_ALGORITHM g_verify_algorithm;
static SM_ALGORITHM g_encrypt_algorithm;
static SM_ALGORITHM g_decrypt_algorithm;


static void init_mac_algorithm();
static void init_hash_algorithm();
static void init_sign_algorithm();
static void init_verify_algorithm();
static void init_encrypt_algorithm();
static void init_decrypt_algorithm();
static int is_length_valid(int plain_data_len, int secret_data_len);
static int make_blob_key(SM_BLOB_KEY *blob_key, PSM_KEY_HANDLE ph_key);
static int make_crypt_algorithm(SM_ALGORITHM *algorithm, const char *hex_iv);


int init_crypto_context() {
    init_hash_algorithm();
    init_mac_algorithm();
    init_sign_algorithm();
    init_verify_algorithm();
    init_encrypt_algorithm();
    init_decrypt_algorithm();

    return YERR_SUCCESS;
}

int crypto_digest(SM_PIPE_HANDLE h_pipe, const char *data, int data_len, char *out, int out_len) {
    if (out_len <= SMMA_SCH_256_LEN * 2) return BUFSIZE_TOO_SMALL;

    char digest[SMMA_SCH_256_LEN * 2] = {0};
    int digest_len = sizeof(digest);
    int error_code = SM_Digest(h_pipe, NULL, &g_hash_algorithm, (PSM_BYTE)data,
                               (SM_UINT)data_len, (PSM_BYTE)digest, (PSM_UINT)&digest_len);
    if (error_code != YERR_SUCCESS) return error_code;

    to_hex(out, out_len, digest, digest_len);

    return YERR_SUCCESS;
}

int crypto_digest_init(SM_PIPE_HANDLE h_pipe) {
    return SM_DigestInit(h_pipe, NULL, &g_hash_algorithm);
}

int crypto_digest_update(SM_PIPE_HANDLE h_pipe, const char *data, int data_len) {
    return SM_DigestUpdate(h_pipe, (PSM_BYTE)data, (SM_UINT)data_len);
}

int crypto_digest_final(SM_PIPE_HANDLE h_pipe, const char *data, int data_len, char *out, int out_len) {
    if (out_len <= SMMA_SCH_256_LEN * 2) return BUFSIZE_TOO_SMALL;

    char digest[SMMA_SCH_256_LEN * 2] = {0};
    int digest_len = sizeof(digest);
    int error_code = SM_DigestFinal(h_pipe, (PSM_BYTE)data, (SM_UINT)data_len, (PSM_BYTE)digest, (PSM_UINT)&digest_len);
    if (error_code != YERR_SUCCESS) return error_code;

    to_hex(out, out_len, digest, digest_len);

    return YERR_SUCCESS;
}

int crypto_random(SM_PIPE_HANDLE h_pipe, char *out, int out_len) {
    int random_len = (out_len - 1) / 2;
    if (random_len > MAX_RANDOM_LEN) return RANDOM_LEN_OUTOF_BOUND;

    char random[MAX_RANDOM_LEN] = {0};
    int error_code = SM_GenRandom(h_pipe, 0, (PSM_BYTE)random, random_len);
    if (error_code != YERR_SUCCESS) return error_code;

    to_hex(out, out_len, random, random_len);

    return YERR_SUCCESS;
}

/* encrypt or decrypt data
 * 1. import key
 * 2. encrypt
 * 3. destroy key */
int crypto_crypt(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_key, bool encrypt,
                 const char *hex_iv, const char *data, int data_len, char *out, int *out_len) {
    int error_code = is_length_valid(data_len, *out_len);
    if (error_code != YERR_SUCCESS) return error_code;

    SM_BLOB_KEY blob_key;
    SM_ALGORITHM algorithm;
    error_code = make_blob_key(&blob_key, ph_key);
    if (error_code != YERR_SUCCESS) return error_code;
    error_code = make_crypt_algorithm(&algorithm, hex_iv);
    if (error_code != YERR_SUCCESS) return error_code;

    if (encrypt) {
        error_code = SM_Encrypt(h_pipe, &blob_key, &algorithm, true, (PSM_BYTE)data,
                                data_len, (PSM_BYTE)out, (PSM_UINT)out_len);
    } else {
        error_code = SM_Decrypt(h_pipe, &blob_key, &algorithm, true, (PSM_BYTE)data,
                                data_len, (PSM_BYTE)out, (PSM_UINT)out_len);
    }
    return error_code;
}

int crypto_crypt_init(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_key, bool encrypt,
                      const char *hex_iv) {
    int error_code = YERR_SUCCESS;

    SM_BLOB_KEY blob_key;
    SM_ALGORITHM algorithm;
    error_code = make_blob_key(&blob_key, ph_key);
    if (error_code != YERR_SUCCESS) return error_code;
    error_code = make_crypt_algorithm(&algorithm, hex_iv);
    if (error_code != YERR_SUCCESS) return error_code;

    if (encrypt) {
        error_code = SM_EncryptInit(h_pipe, &blob_key, &algorithm);
    } else {
        error_code = SM_DecryptInit(h_pipe, &blob_key, &algorithm);
    }
    return error_code;
}

int crypto_crypt_update(SM_PIPE_HANDLE h_pipe, bool encrypt, const char *data, int data_len, char *out, int *out_len) {
    if (data_len != SMMA_ALG35_BLOCK_LEN) return BLOCK_LENGTH_INVALID;
    if (*out_len < data_len) return BUFSIZE_TOO_SMALL;

    int error_code = YERR_SUCCESS;

    if (encrypt) {
        error_code = SM_EncryptUpdate(h_pipe, (PSM_BYTE)data, data_len, (PSM_BYTE)out, (PSM_UINT)out_len);
    } else {
        error_code = SM_DecryptUpdate(h_pipe, (PSM_BYTE)data, data_len, (PSM_BYTE)out, (PSM_UINT)out_len);
    }

    return error_code;
}

int crypto_crypt_final(SM_PIPE_HANDLE h_pipe, bool encrypt, const char *data, int data_len, char *out, int *out_len) {
    int error_code = is_length_valid(data_len, *out_len);
    if (error_code != YERR_SUCCESS) return error_code;

    if (encrypt) {
        error_code = SM_EncryptFinal(h_pipe, true, (PSM_BYTE)data, data_len, (PSM_BYTE)out, (PSM_UINT)out_len);
    } else {
        error_code = SM_DecryptFinal(h_pipe, true, (PSM_BYTE)data, data_len, (PSM_BYTE)out, (PSM_UINT)out_len);
    }

    return YERR_SUCCESS;
}

int crypto_ecc_sign(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_key,
                    const char *hex_data, char *hex_out, int hex_out_len) {
    int hex_data_len = strlen(hex_data);
    if (hex_data_len / 2 < SMMA_ECC_FP_256_SIG_MIN_LEN || hex_data_len / 2 > SMMA_ECC_FP_256_SIG_MAX_LEN) {
        return BLOCK_LENGTH_INVALID;
    }
    if (hex_out_len <= SMMA_ECC_FP_256_SIG_MAX_LEN * 2) {
        return BUFSIZE_TOO_SMALL;
    }

    SM_BLOB_KEY blob_key;
    int error_code = make_blob_key(&blob_key, ph_key);
    if (error_code != YERR_SUCCESS) return error_code;

    char data[SMMA_ECC_FP_256_SIG_MAX_LEN] = {0};
    int data_len = 0;
    from_hex(data, &data_len, hex_data);
    assert(data_len <= sizeof(data));

    char out[SMMA_ECC_FP_256_SIG_MAX_LEN] = {0};
    int out_len = sizeof(out);

    error_code = SM_ECCSignature(h_pipe, &blob_key, &g_sign_algorithm,
                                 (PSM_BYTE)data, (SM_UINT)data_len,
                                 (PSM_BYTE)out, (PSM_UINT)&out_len);
    if (error_code != YERR_SUCCESS) return error_code;
    to_hex(hex_out, hex_out_len, out, out_len);
    return YERR_SUCCESS;
}

int crypto_ecc_verify(SM_PIPE_HANDLE h_pipe, const char *hex_key, int *verify_result,
                      const char *hex_data, char *hex_signature) {
    int hex_data_len = strlen(hex_data);
    int hex_signature_len = strlen(hex_signature);
    if (strlen(hex_key) != SMMA_ECC_FP_256_PUBLIC_KEY_LEN * 2) return KEY_LENGTH_INVALID;
    if (hex_data_len / 2 < SMMA_ECC_FP_256_SIG_MIN_LEN || hex_data_len / 2 > SMMA_ECC_FP_256_SIG_MAX_LEN) {
        return BLOCK_LENGTH_INVALID;
    }
    if (hex_signature_len != SMMA_ECC_FP_256_SIG_VALLEN * 2) {
        return BLOCK_LENGTH_INVALID;
    }

    char public_key[SMMA_ECC_FP_256_PUBLIC_KEY_LEN] = {0};
    int pubkey_len = 0;
    from_hex(public_key, &pubkey_len,  hex_key);
    assert(pubkey_len <= sizeof(public_key));

    char data[SMMA_ECC_FP_256_SIG_MAX_LEN] = {0};
    int data_len = 0;
    from_hex(data, &data_len, hex_data);
    assert(data_len <= sizeof(data));

    char signature[SMMA_ECC_FP_256_SIG_VALLEN] = {0};
    int signature_len = 0;
    from_hex(signature, &signature_len, hex_signature);
    assert(signature_len <= sizeof(signature));

    SM_BLOB_KEY blob_key;
    memset(&blob_key, 0, sizeof(SM_BLOB_KEY));
    blob_key.pbyData = (PSM_BYTE)public_key;
    blob_key.uiDataLen = (SM_UINT)pubkey_len;

    int error_code = SM_ECCVerify(h_pipe, &blob_key, &g_verify_algorithm,
                                  (PSM_BYTE)data, (SM_UINT)data_len,
                                  (PSM_BYTE)signature, (SM_UINT)signature_len);
    *verify_result = error_code;
    return YERR_SUCCESS;
}

/**
 * TODO
 */
//int crypto_ecc_encrypt(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_key, const char *hex_data, char *hex_out, int hex_out_len) {
//    int hex_data_len = strlen(hex_data);
//    if (hex_data_len / 2 > MAX_ECC_ENCRYPT_LEN) {
//        return BLOCK_LENGTH_INVALID;
//    }
//    if (hex_out_len <= MAX_ECC_ENCRYPT_LEN * 4) {
//        return BUFSIZE_TOO_SMALL;
//    }
//
//    SM_BLOB_KEY blob_key;
//    int error_code = make_blob_key(&blob_key, ph_key);
//    if (error_code != YERR_SUCCESS) return error_code;
//
//    char data[MAX_ECC_ENCRYPT_LEN] = {0};
//    int data_len = 0;
//    from_hex(data, &data_len, hex_data);
//    assert(data_len <= sizeof(data));
//
//    SM_BLOB_ECCCIPHER st_ecc_cipher;
//    memset(&st_ecc_cipher, 0, sizeof(SM_BLOB_ECCCIPHER));
//
//    error_code = SM_ECCEncrypt(h_pipe, &blob_key, &g_encrypt_algorithm,
//                               (PSM_BYTE)data, (SM_UINT)data_len, &st_ecc_cipher);
//    if (error_code != YERR_SUCCESS) return error_code;
//
//    return YERR_SUCCESS;
//}

static void init_hash_algorithm() {
    memset(&g_hash_algorithm, 0, sizeof(SM_ALGORITHM));
    g_hash_algorithm.AlgoType = SMM_SCH_256;
    g_hash_algorithm.pParameter = SM_NULL;
    g_hash_algorithm.uiParameterLen = SMMA_SCH_256_LEN;
}

static void init_mac_algorithm() {
    memset(&g_mac_algorithm, 0, sizeof(SM_ALGORITHM));
    g_mac_algorithm.AlgoType = SMM_ALG35_MAC;
    g_mac_algorithm.pParameter = g_byiv;
    g_mac_algorithm.uiParameterLen = SMMA_ALG34_IV_LEN;
}

static void init_sign_algorithm() {
    memset(&g_sign_algorithm, 0, sizeof(SM_ALGORITHM));
    g_sign_algorithm.AlgoType = SMM_ECC_FP_SIGN;
    g_sign_algorithm.pParameter = SM_NULL;
    g_sign_algorithm.uiParameterLen = 0;
    g_sign_algorithm.uiReserve = SMMA_ECC_FP_256_MODULUS_BITS;
}

static void init_verify_algorithm() {
    memset(&g_verify_algorithm, 0, sizeof(SM_ALGORITHM));
    g_verify_algorithm.AlgoType = SMM_ECC_FP_VERIFY;
    g_verify_algorithm.pParameter = SM_NULL;
    g_verify_algorithm.uiParameterLen = 0;
    g_verify_algorithm.uiReserve = SMMA_ECC_FP_256_MODULUS_BITS;
}

static void init_encrypt_algorithm() {
    memset(&g_encrypt_algorithm, 0, sizeof(SM_ALGORITHM));
    g_encrypt_algorithm.AlgoType = SMM_ECC_FP_ENC;
    g_encrypt_algorithm.pParameter = SM_NULL;
    g_encrypt_algorithm.uiParameterLen = 0;
    g_encrypt_algorithm.uiReserve = SMMA_ECC_FP_256_MODULUS_BITS;
}

static void init_decrypt_algorithm() {
    memset(&g_decrypt_algorithm, 0, sizeof(SM_ALGORITHM));
    g_decrypt_algorithm.AlgoType = SMM_ECC_FP_DEC;
    g_decrypt_algorithm.pParameter = SM_NULL;
    g_decrypt_algorithm.uiParameterLen = 0;
    g_decrypt_algorithm.uiReserve = SMMA_ECC_FP_256_MODULUS_BITS;
}

static int is_length_valid(int plain_data_len, int secret_data_len) {
    int block_len = SMMA_ALG35_BLOCK_LEN;
    int expected_len = (plain_data_len / block_len + 1) * block_len;
    if (secret_data_len < expected_len) return BUFSIZE_TOO_SMALL;
    return YERR_SUCCESS;
}

static int make_blob_key(SM_BLOB_KEY *blob_key, PSM_KEY_HANDLE ph_key) {
    memset(blob_key, 0, sizeof(SM_BLOB_KEY));
    blob_key->pbyData = (SM_BYTE*)ph_key;
    blob_key->uiDataLen = sizeof(SM_KEY_HANDLE);
    return YERR_SUCCESS;
}

static int make_crypt_algorithm(SM_ALGORITHM *algorithm, const char *hex_iv) {
    if (NULL != hex_iv) {
        if (strlen(hex_iv) != SMMA_ALG35_BLOCK_LEN * 2) return IV_LENGTH_INVALID;
    }

    memset(algorithm, 0, sizeof(SM_ALGORITHM));
    if (NULL != hex_iv) {
        char iv[SMMA_ALG35_BLOCK_LEN] = {0};
        int iv_len = sizeof(iv);
        from_hex(iv, &iv_len, hex_iv);
        algorithm->AlgoType = SMM_ALG35_CBC;
        algorithm->pParameter = iv;
        algorithm->uiParameterLen = SMMA_ALG35_IV_LEN;
    } else {
        algorithm->AlgoType = SMM_ALG35_ECB;
        algorithm->pParameter = NULL;
        algorithm->uiParameterLen = 0;
    }

    return YERR_SUCCESS;
}

//add by lr
int crypto_ecc_enc(SM_PIPE_HANDLE h_pipe, const char *hex_key,
         const char *hex_data,char *hex_out, int hex_out_len) {    
  if (strlen(hex_key) != SMMA_ECC_FP_256_PUBLIC_KEY_LEN * 2) return KEY_LENGTH_INVALID;   
  char public_key[SMMA_ECC_FP_256_PUBLIC_KEY_LEN] = {0};
  int pubkey_len = 0;
  from_hex(public_key, &pubkey_len,  hex_key);  
  char data[1024] = {0};
  int data_len = 0;
  from_hex(data, &data_len, hex_data);
              
  SM_BLOB_KEY blob_key;
  memset(&blob_key, 0, sizeof(SM_BLOB_KEY));
  blob_key.pbyData = (PSM_BYTE)public_key;
  blob_key.uiDataLen = (SM_UINT)pubkey_len;
        
  SM_BLOB_ECCCIPHER	stEccCipher;
  memset(&stEccCipher, 0, sizeof(SM_BLOB_ECCCIPHER));
  int error_code = SM_ECCEncrypt(h_pipe, &blob_key, &g_encrypt_algorithm,
                               (PSM_BYTE)data, (SM_UINT)data_len, &stEccCipher);
  if (error_code != YERR_SUCCESS) return error_code;

  SM_UINT uiCipherLen = 0;
  uiCipherLen = stEccCipher.uiCheckDataLen + stEccCipher.uiCipherDataLen + stEccCipher.uiSessionKeyLen;
  char out[2048] = {0};
  int out_len = uiCipherLen;
  stEccCipher.pbyData = (PSM_BYTE)out;	
  error_code = SM_ECCEncrypt(h_pipe, &blob_key, &g_encrypt_algorithm,
                                (PSM_BYTE)data, (SM_UINT)data_len, &stEccCipher);
                                                                                                	                                          
  if (error_code != YERR_SUCCESS) return error_code;
  to_hex(hex_out, hex_out_len, out, out_len);
  return YERR_SUCCESS;
}


int crypto_ecc_dec(SM_PIPE_HANDLE h_pipe, PSM_KEY_HANDLE ph_key,
                   const char *hex_data, char *hex_out, int hex_out_len) {
                                                                                                          	                                                                                  
   SM_BLOB_KEY blob_key;
   int error_code = make_blob_key(&blob_key, ph_key);
   if (error_code != YERR_SUCCESS) return error_code;
   char data[2048] = {0};
   int data_len = 0;
   from_hex(data, &data_len, hex_data);
                                                       	                                                                                                              
   SM_BLOB_ECCCIPHER	stECCCipher;
   stECCCipher.pbyData = (SM_BYTE*)data;
   stECCCipher.uiCheckDataLen = SMMA_SCH_256_LEN;
                                                                                                                                              	                                                                                                                           	stECCCipher.uiSessionKeyLen = SMMA_ECC_FP_256_PUBLIC_KEY_LEN;
  stECCCipher.uiCipherDataLen = data_len-SMMA_SCH_256_LEN-SMMA_ECC_FP_256_PUBLIC_KEY_LEN;
  SM_UINT             uiPlainDataLen = 0;
                                                                                                                            	                                                                                                                           		        error_code = SM_ECCDecrypt(h_pipe, &blob_key, &g_decrypt_algorithm,&stECCCipher, SM_NULL, &uiPlainDataLen);
  if (error_code != YERR_SUCCESS) return error_code;
  char out[2048] = {0};
  int out_len = uiPlainDataLen;
  error_code = SM_ECCDecrypt(h_pipe, &blob_key, &g_decrypt_algorithm,&stECCCipher, (SM_BYTE*)out, &uiPlainDataLen);
  if (error_code != YERR_SUCCESS) return error_code;
  to_hex(hex_out, hex_out_len, out, out_len);
  return YERR_SUCCESS;
}



/*
 * uiSessionKeyLen: 4 bytes
 * uiCipherDataLen: 4 bytes
 * uiCheckDataLen: 4 bytes
 * "uiSessionKeyLen uiCipherDataLen uiCheckDataLen hexStream"
 **/
//static int formatEccCipher(PSM_BLOB_ECCCIPHER pst_ecc_cipher, char *hex_out, int hex_out_len) {
//    PSM_BLOB_ECCCIPHER cipher = pst_ecc_cipher;
//    int total_len = (cipher->uiSessionKeyLen + cipher->uiCipherDataLen + cipher->uiCheckDataLen) * 2 + 16;
//    if (hex_out_len < total_len) {
//        return BUFSIZE_TOO_SMALL;
//    }
//
//    int delta = sprintf(hex_out, "%4d %4d %4d ",
//                        cipher->uiSessionKeyLen, cipher->uiCipherDataLen, cipher->uiCheckDataLen);
//    hex_out += delta;
//    to_hex(hex_out, hex_out_len - delta, cipher->pbyData,
//           cipher->uiSessionKeyLen + cipher->uiCipherDataLen + cipher->uiCheckDataLen);
//
//    return YERR_SUCCESS;
//}
//
//static char *nex_chip(char *str, char *chip, int chip_len, char sep) {
//    char *cipher = str;
//
//    while (cipher != NULL && (*cipher) != sep) cipher++;
//    while ((*cipher) == sep) cipher++;
//
//    if (cipher - str > chip_len) return NULL;
//
//    strncpy(chip, str, cipher - str);
//
//    return cipher;
//}
//
//static int loadEccCipher(PSM_BLOB_ECCCIPHER pst_ecc_cipher, char *hex_data) {
//    char chip[4] = {0};
//
//    char *cursor = hex_data;
//
//    cursor = nex_chip(cursor, chip, sizeof(chip), ' ');
//    if (NULL == cursor) return YERR_FORMAT_ERROR;
//    pst_ecc_cipher->uiSessionKeyLen = atoi(chip);
//
//    cursor = nex_chip(cursor, chip, sizeof(chip), ' ');
//    if (NULL == cursor) return YERR_FORMAT_ERROR;
//    pst_ecc_cipher->uiCipherDataLen = atoi(chip);
//
//    cursor = nex_chip(cursor, chip, sizeof(chip), ' ');
//    if (NULL == cursor) return YERR_FORMAT_ERROR;
//    pst_ecc_cipher->uiCheckDataLen = atoi(chip);
//
//    // TODO
//    return YERR_SUCCESS;
//}
