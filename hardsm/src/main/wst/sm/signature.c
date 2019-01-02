#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "../include/base64.h"
#include "../include/util.h"
#include "../include/sm.h"


extern Handles g_handles;


/* fill a str to buf, return pointer at tail */
static char *fill_buf(char *buf, const char *key, const char *str) {
    if (NULL == buf || NULL == key || NULL == str || strlen(str) <=0) 
        return buf;

    int delta = strlen(key) + strlen(str) + 2;
    snprintf(buf, delta, "%s:%s", key, str);
    buf += delta;
    return buf;
}


static Result format_signature(Signature *signature, char *buf, int *buf_len) {
    assert(NULL != signature && NULL != buf && NULL != buf_len);
    Result result = init_result();

    if (strlen(signature->vs) == 0) {
        strncpy(result.msg, "version field is required for signature\n", 
                sizeof(result.msg));
        goto fail;
    }
    if (strlen(signature->dh) == 0) {
        strncpy(result.msg, "data hash field is required for signature\n", 
                sizeof(result.msg));
        goto fail;
    }
    // if (strlen(signature->cs) == 0) goto fail;  custom data is optional
    if (strlen(signature->ts) == 0) {
        strncpy(result.msg, "timestamp field is required for signature\n", 
                sizeof(result.msg));
        goto fail;
    }
    if (strlen(signature->mc) == 0) {
        strncpy(result.msg, "machine code field is required for signature\n", 
                sizeof(result.msg));
        goto fail;
    }
    if (strlen(signature->ct) == 0) {
        strncpy(result.msg, "cert field is required for signature\n", 
                sizeof(result.msg));
        goto fail;
    }
    // if (strlen(signature->sg) == 0) goto fail;

    char *cursor = buf;
    cursor = fill_buf(cursor, SIG_KEY_VS, signature->vs);
    cursor = fill_buf(cursor, SIG_KEY_DH, signature->dh);
    cursor = fill_buf(cursor, SIG_KEY_CS, signature->cs);
    cursor = fill_buf(cursor, SIG_KEY_TS, signature->ts);
    cursor = fill_buf(cursor, SIG_KEY_MC, signature->mc);
    cursor = fill_buf(cursor, SIG_KEY_CT, signature->ct);
    // sg should be the last one
    cursor = fill_buf(cursor, SIG_KEY_SG, signature->sg);

    *buf_len = cursor - buf;
    return result;


fail:
    result.code = YERR_FORMAT_ERROR;
    return result;
}


/* format signature and base64 encode */
Result gen_signature(Signature *signature, char *b64str) {
    Result result = init_result();

    char buf[MAX_SIGNATURE_LEN + 1] = {0};
    int buf_len = sizeof(buf);
    result = format_signature(signature, buf, &buf_len);
    if (result.code != YERR_SUCCESS) return result;

    Base64encode(b64str, buf, buf_len);

    return result;
}


Result load_signature(const char *b64_sig, Signature *signature) {
    assert(NULL != b64_sig && NULL != signature);
    Result result = init_result();

    int buf_len = 0;
    char *buf = (char *)malloc(strlen(b64_sig) + 1);
    buf_len = Base64decode(buf, b64_sig);
    char *cursor = buf;
    const char separator = ':';
    int chip_size = strlen(b64_sig) + 1;
    char *key_chip = (char *)malloc(chip_size);
    char *value_chip = (char *)malloc(chip_size);
    int exists_bitmap = 0;

    while (cursor < buf + buf_len) {
        if (*cursor == 0) {
            cursor++;
            continue;
        }

        if (count_chips(cursor, separator) < 2) goto fail;

        char *next = cursor;
        /* get key */
        memset(key_chip, 0, chip_size);
        next = (char *)next_chip((const char *)next, separator, key_chip);
        if (strlen(key_chip) > MAX_SIG_KEY_LEN) goto fail;
        /* get value */
        memset(value_chip, 0, chip_size);
        strncpy(value_chip, cursor + strlen(key_chip) + 1, chip_size);

        /* match and fill */
        if (0 == strcmp(key_chip, SIG_KEY_VS)) {
            exists_bitmap |= SIG_KEY_VS_BIT;
            strncpy(signature->vs, value_chip, sizeof(signature->vs));
        } else if (0 == strcmp(key_chip, SIG_KEY_DH)) {
            exists_bitmap |= SIG_KEY_DH_BIT;
            strncpy(signature->dh, value_chip, sizeof(signature->dh));
        } else if (0 == strcmp(key_chip, SIG_KEY_CS)) {
            // exists_bitmap |= SIG_KEY_CS_BIT;
            strncpy(signature->cs, value_chip, sizeof(signature->cs));
        } else if (0 == strcmp(key_chip, SIG_KEY_TS)) {
            exists_bitmap |= SIG_KEY_TS_BIT;
            strncpy(signature->ts, value_chip, sizeof(signature->ts));
        } else if (0 == strcmp(key_chip, SIG_KEY_MC)) {
            exists_bitmap |= SIG_KEY_MC_BIT;
            strncpy(signature->mc, value_chip, sizeof(signature->mc));
        } else if (0 == strcmp(key_chip, SIG_KEY_CT)) {
            exists_bitmap |= SIG_KEY_CT_BIT;
            strncpy(signature->ct, value_chip, sizeof(signature->ct));
        } else if (0 == strcmp(key_chip, SIG_KEY_SG)) {
            // exists_bitmap |= SIG_KEY_SG_BIT;
            strncpy(signature->sg, value_chip, sizeof(signature->sg));
        } else {
        }
        cursor += strlen(cursor);
    }

    if (exists_bitmap != SIG_KEY_ALL_BITS) goto fail;
    free(key_chip);
    free(value_chip);
    free(buf);

    return result;


fail:
    free(key_chip);
    free(value_chip);
    free(buf);
    result.code = YERR_FORMAT_ERROR;
    strncpy(result.msg, "signature format error\n", sizeof(result.msg));
    return result;
}


Result sign_signature(Signature *signature, const char *hex_private, 
                      OUT char *b64_signature) {
    Result result = init_result();

    /* format signature structure into a binary buf */
    char formatted_sig[MAX_SIGNATURE_LEN + 1] = {0};
    int formatted_sig_len = sizeof(formatted_sig);
    *(signature->sg) = 0;    // clear sg field
    result = format_signature(signature, formatted_sig, &formatted_sig_len);

    if (result.code != YERR_SUCCESS) return result;

    /* sign formatted sig */
    char sig_value[MAX_SIGVALUE_LENGTH + 1] = {0};
    int sig_value_len = 0;
    result = sm2_sign(hex_private, formatted_sig, 
                      formatted_sig_len, sig_value, &sig_value_len);

    if (result.code != YERR_SUCCESS) return result;

    /* fill signature into signature struct */
    to_hex(signature->sg, sizeof(signature->sg), sig_value, sig_value_len);

    /* generate signed signature */
    result = gen_signature(signature, b64_signature);

    return result;
}


Result verify_signature(const char *b64_sig, const char *hex_public, 
                        int *verify_result) {
    Result result = init_result();
    Result tmp = init_result();
    int ret = YERR_SUCCESS;

    /* unpack signature */
    /* verify result is false if failed to unpack */
    Signature signature;
    memset(&signature, 0, sizeof(signature));
    tmp = load_signature(b64_sig, &signature);
    if (tmp.code != YERR_SUCCESS) {
        *verify_result = UNIFY_ERROR_CODE(tmp.code);
        return result;
    }

    if (NULL == signature.sg || strlen(signature.sg) == 0) {
        *verify_result = UNIFY_ERROR_CODE(YERR_MISS_SIGNATURE);
        return result;
    }

    /* get signature out */
    char sig[MAX_SIGNATURE_LEN + 1] = {0};
    int sig_len;
    ret = from_hex(sig, &sig_len, signature.sg);
    if (ret != YERR_SUCCESS) {
        *verify_result = UNIFY_ERROR_CODE(ret);
        return result;
    }
    *(signature.sg) = 0;    // clear sg field

    /* format signature structure into a binary buf */
    char formatted_sig[MAX_SIGNATURE_LEN + 1] = {0};
    int formatted_sig_len = sizeof(formatted_sig);
    tmp = format_signature(&signature, formatted_sig, &formatted_sig_len);
    if (tmp.code != YERR_SUCCESS) {
        *verify_result = UNIFY_ERROR_CODE(tmp.code);
        return result;
    }

    /* verify signature */
    result = sm2_verify(hex_public, formatted_sig, formatted_sig_len, sig, 
                        sig_len, verify_result);
    return result;
}
