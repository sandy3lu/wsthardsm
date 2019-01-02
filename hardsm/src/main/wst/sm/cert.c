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


/* load cert key-values into binary buf,
   buf size should be large enough, 1k is fine */
static Result format_cert(MinimalCert *minimal_cert, char *buf, int *buf_len) {
    assert(NULL != minimal_cert && NULL != buf && NULL != buf_len);
    Result result = init_result();

    if (NULL == minimal_cert->vs || strlen(minimal_cert->vs) == 0) {
        strncpy(result.msg, "version field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->pk || strlen(minimal_cert->pk) == 0) {
        strncpy(result.msg, "public key field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->pd || strlen(minimal_cert->pd) == 0) {
        strncpy(result.msg, "parent cert digest field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->da || strlen(minimal_cert->da) == 0) {
        strncpy(result.msg,
                "parent cert digest algorithm field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->sd || strlen(minimal_cert->sd) == 0) {
        strncpy(result.msg, "start date field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->ed || strlen(minimal_cert->ed) == 0) {
        strncpy(result.msg, "end date field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->lv || strlen(minimal_cert->lv) == 0) {
        strncpy(result.msg, "level field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->ts || strlen(minimal_cert->ts) == 0) {
        strncpy(result.msg, "timestamp field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }

    if (NULL == minimal_cert->mf || strlen(minimal_cert->mf) == 0) {
        strncpy(result.msg, "manufacture field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->ag || strlen(minimal_cert->ag) == 0) {
        strncpy(result.msg, "algorithm field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->bt || strlen(minimal_cert->bt) == 0) {
        strncpy(result.msg, "bit length field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->fg || strlen(minimal_cert->fg) == 0) {
        strncpy(result.msg, "flag field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }

    if (NULL == minimal_cert->cn || strlen(minimal_cert->cn) == 0) {
        strncpy(result.msg, "country field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->iu || strlen(minimal_cert->iu) == 0) {
        strncpy(result.msg, "issuer field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->sc || strlen(minimal_cert->sc) == 0) {
        strncpy(result.msg, "seal code field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->sn || strlen(minimal_cert->sn) == 0) {
        strncpy(result.msg, "seal name field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->st || strlen(minimal_cert->st) == 0) {
        strncpy(result.msg, "seal type field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->un || strlen(minimal_cert->un) == 0) {
        strncpy(result.msg, "use unit field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    if (NULL == minimal_cert->id || strlen(minimal_cert->id) == 0) {
        strncpy(result.msg, "identify field is required for cert\n",
                sizeof(result.msg));
        goto fail;
    }
    // if (NULL == minimal_cert->sg || strlen(minimal_cert->sg) == 0) goto fail;
    // unsigned cert and signed cert

    char *cursor = buf;

    cursor = fill_buf(cursor, CERT_KEY_AG, minimal_cert->ag);
    cursor = fill_buf(cursor, CERT_KEY_BT, minimal_cert->bt);
    cursor = fill_buf(cursor, CERT_KEY_CN, minimal_cert->cn);
    cursor = fill_buf(cursor, CERT_KEY_DA, minimal_cert->da);
    cursor = fill_buf(cursor, CERT_KEY_ED, minimal_cert->ed);
    cursor = fill_buf(cursor, CERT_KEY_FG, minimal_cert->fg);
    cursor = fill_buf(cursor, CERT_KEY_ID, minimal_cert->id);
    cursor = fill_buf(cursor, CERT_KEY_IU, minimal_cert->iu);
    cursor = fill_buf(cursor, CERT_KEY_LV, minimal_cert->lv);
    cursor = fill_buf(cursor, CERT_KEY_MF, minimal_cert->mf);
    cursor = fill_buf(cursor, CERT_KEY_PD, minimal_cert->pd);
    cursor = fill_buf(cursor, CERT_KEY_PK, minimal_cert->pk);
    cursor = fill_buf(cursor, CERT_KEY_SC, minimal_cert->sc);
    cursor = fill_buf(cursor, CERT_KEY_SD, minimal_cert->sd);
    cursor = fill_buf(cursor, CERT_KEY_SN, minimal_cert->sn);
    cursor = fill_buf(cursor, CERT_KEY_ST, minimal_cert->st);
    cursor = fill_buf(cursor, CERT_KEY_TS, minimal_cert->ts);
    cursor = fill_buf(cursor, CERT_KEY_UN, minimal_cert->un);
    cursor = fill_buf(cursor, CERT_KEY_VS, minimal_cert->vs);
    cursor = fill_buf(cursor, CERT_KEY_SG, minimal_cert->sg);

    *buf_len = cursor - buf;
    return result;

fail:
    result.code = YERR_FORMAT_ERROR;
    return result;
}

/* format cert and base64 encode */
Result gen_cert(MinimalCert *minimal_cert, char *b64str) {
    Result result = init_result();

    char buf[MAX_CERT_LEN + 1] = {0};
    int buf_len = sizeof(buf);
    result = format_cert(minimal_cert, buf, &buf_len);
    if (result.code != YERR_SUCCESS) return result;

    Base64encode(b64str, buf, buf_len);
    return result;
}

/* load base64 encoded cert to cert structure */
/* 1. key length should not more than MAX_CERT_KEY_LEN
 * 2. all necessary keys are needed
 * 3. key:value format
 */
Result load_cert(const char *b64_cert, MinimalCert *minimal_cert) {
    assert(NULL != b64_cert && NULL != minimal_cert);
    Result result = init_result();

    int buf_len = 0;
    char *buf = (char *)malloc(strlen(b64_cert) + 1);
    buf_len = Base64decode(buf, b64_cert);
    char *cursor = buf;
    const char separator = ':';
    int chip_size = strlen(b64_cert) + 1;
    char *key_chip = (char *)malloc(chip_size);
    char *value_chip = (char *)malloc(chip_size);
    int exists_bitmap = 0;

    while (cursor < buf + buf_len) {
        if (count_chips(cursor, separator) < 2) goto fail;

        char *next = cursor;
        /* get key */
        memset(key_chip, 0, chip_size);
        next = (char *)next_chip((const char *)next, separator, key_chip);
        if (strlen(key_chip) > MAX_CERT_KEY_LEN) goto fail;
        /* get value */
        memset(value_chip, 0, chip_size);
        strncpy(value_chip, cursor + strlen(key_chip) + 1, chip_size);

        /* match and fill */
        if (0 == strcmp(key_chip, CERT_KEY_VS)) {
            exists_bitmap |= CERT_KEY_VS_BIT;
            strncpy(minimal_cert->vs, value_chip, sizeof(minimal_cert->vs));
        } else if (0 == strcmp(key_chip, CERT_KEY_PK)) {
            exists_bitmap |= CERT_KEY_PK_BIT;
            strncpy(minimal_cert->pk, value_chip, sizeof(minimal_cert->pk));
        } else if (0 == strcmp(key_chip, CERT_KEY_PD)) {
            exists_bitmap |= CERT_KEY_PD_BIT;
            strncpy(minimal_cert->pd, value_chip, sizeof(minimal_cert->pd));
        } else if (0 == strcmp(key_chip, CERT_KEY_DA)) {
            exists_bitmap |= CERT_KEY_DA_BIT;
            strncpy(minimal_cert->da, value_chip, sizeof(minimal_cert->da));
        } else if (0 == strcmp(key_chip, CERT_KEY_SG)) {
            // exists_bitmap |= CERT_KEY_SG_BIT;  this field is not necessary
            strncpy(minimal_cert->sg, value_chip, sizeof(minimal_cert->sg));
        } else if (0 == strcmp(key_chip, CERT_KEY_SD)) {
            exists_bitmap |= CERT_KEY_SD_BIT;
            strncpy(minimal_cert->sd, value_chip, sizeof(minimal_cert->sd));
        } else if (0 == strcmp(key_chip, CERT_KEY_ED)) {
            exists_bitmap |= CERT_KEY_ED_BIT;
            strncpy(minimal_cert->ed, value_chip, sizeof(minimal_cert->ed));
        } else if (0 == strcmp(key_chip, CERT_KEY_LV)) {
            exists_bitmap |= CERT_KEY_LV_BIT;
            strncpy(minimal_cert->lv, value_chip, sizeof(minimal_cert->lv));
        } else if (0 == strcmp(key_chip, CERT_KEY_TS)) {
            exists_bitmap |= CERT_KEY_TS_BIT;
            strncpy(minimal_cert->ts, value_chip, sizeof(minimal_cert->ts));
        } else if (0 == strcmp(key_chip, CERT_KEY_MF)) {
            exists_bitmap |= CERT_KEY_MF_BIT;
            strncpy(minimal_cert->mf, value_chip, sizeof(minimal_cert->mf));
        } else if (0 == strcmp(key_chip, CERT_KEY_AG)) {
            exists_bitmap |= CERT_KEY_AG_BIT;
            strncpy(minimal_cert->ag, value_chip, sizeof(minimal_cert->ag));
        } else if (0 == strcmp(key_chip, CERT_KEY_BT)) {
            exists_bitmap |= CERT_KEY_BT_BIT;
            strncpy(minimal_cert->bt, value_chip, sizeof(minimal_cert->bt));
        } else if (0 == strcmp(key_chip, CERT_KEY_FG)) {
            exists_bitmap |= CERT_KEY_FG_BIT;
            strncpy(minimal_cert->fg, value_chip, sizeof(minimal_cert->fg));
        } else if (0 == strcmp(key_chip, CERT_KEY_CN)) {
            exists_bitmap |= CERT_KEY_CN_BIT;
            strncpy(minimal_cert->cn, value_chip, sizeof(minimal_cert->cn));
        } else if (0 == strcmp(key_chip, CERT_KEY_IU)) {
            exists_bitmap |= CERT_KEY_IU_BIT;
            strncpy(minimal_cert->iu, value_chip, sizeof(minimal_cert->iu));
        } else if (0 == strcmp(key_chip, CERT_KEY_SC)) {
            exists_bitmap |= CERT_KEY_SC_BIT;
            strncpy(minimal_cert->sc, value_chip, sizeof(minimal_cert->sc));
        } else if (0 == strcmp(key_chip, CERT_KEY_SN)) {
            exists_bitmap |= CERT_KEY_SN_BIT;
            strncpy(minimal_cert->sn, value_chip, sizeof(minimal_cert->sn));
        } else if (0 == strcmp(key_chip, CERT_KEY_ST)) {
            exists_bitmap |= CERT_KEY_ST_BIT;
            strncpy(minimal_cert->st, value_chip, sizeof(minimal_cert->st));
        } else if (0 == strcmp(key_chip, CERT_KEY_UN)) {
            exists_bitmap |= CERT_KEY_UN_BIT;
            strncpy(minimal_cert->un, value_chip, sizeof(minimal_cert->un));
        } else if (0 == strcmp(key_chip, CERT_KEY_ID)) {
            exists_bitmap |= CERT_KEY_ID_BIT;
            strncpy(minimal_cert->id, value_chip, sizeof(minimal_cert->id));
        } else {
        }
        cursor += strlen(cursor);
        while (*cursor == 0) cursor++;
    }
    if (exists_bitmap != CERT_KEY_ALL_BITS) goto fail;

    free(key_chip);
    free(value_chip);
    free(buf);
    return result;


fail:
    free(key_chip);
    free(value_chip);
    free(buf);
    result.code = YERR_FORMAT_ERROR;
    strncpy(result.msg, "cert format error\n", sizeof(result.msg));
    return result;
}


/* 1. format cert info without signature
 * 2. sign cert info get signature
 * 3. add signature to cert info
 * 4. generate signed cert
 * this will modify the sg field of minimal_cert
 */
Result sign_cert(MinimalCert *minimal_cert, const char *hex_private,
                 OUT char *b64_cert) {
    Result result = init_result();

    /* format cert information into a binary buf */
    char formatted_cert[MAX_CERT_LEN + 1] = {0};
    int formatted_cert_len = sizeof(formatted_cert);
    *(minimal_cert->sg) = 0;    // clear sg field
    result = format_cert(minimal_cert, formatted_cert, &formatted_cert_len);
    if (result.code != YERR_SUCCESS) return result;

    /* sign formatted cert */
    char sig_value[MAX_SIGVALUE_LENGTH + 1] = {0};
    int sig_value_len = 0;
    result = sm2_sign(hex_private, formatted_cert, formatted_cert_len,
                      sig_value, &sig_value_len);
    if (result.code != YERR_SUCCESS) return result;

    /* fill signature into cert struct */
    to_hex(minimal_cert->sg, sizeof(minimal_cert->sg),
           sig_value, sig_value_len);

    /* generate signed cert */
    result = gen_cert(minimal_cert, b64_cert);

    return result;
}


/* 1. format cert without signature, get original data
 * 2. verify
 */
Result verify_cert(const char *b64_cert, const char *hex_public,
                   bool *verify_result) {
    Result result = init_result();
    Result tmp = init_result();
    int ret = YERR_SUCCESS;

    /* unpack cert */
    /* verify result is false if failed to unpack */
    MinimalCert minimal_cert;
    memset(&minimal_cert, 0, sizeof(minimal_cert));
    tmp = load_cert(b64_cert, &minimal_cert);
    if (tmp.code != YERR_SUCCESS) {
        *verify_result = UNIFY_ERROR_CODE(tmp.code);
        return result;
    }

    if (NULL == minimal_cert.sg || strlen(minimal_cert.sg) == 0) {
        *verify_result = UNIFY_ERROR_CODE(YERR_MISS_SIGNATURE);
        return result;
    }

    /* get signature out */
    char sig[MAX_SIGNATURE_LEN + 1] = {0};
    int sig_len;
    ret = from_hex(sig, &sig_len, minimal_cert.sg);
    if (ret != YERR_SUCCESS) {
        *verify_result = UNIFY_ERROR_CODE(ret);
        return result;
    }
    *(minimal_cert.sg) = 0;    // clear sg field

    /* format cert information into a binary buf */
    char formatted_cert[MAX_CERT_LEN + 1] = {0};
    int formatted_cert_len = sizeof(formatted_cert);
    tmp = format_cert(&minimal_cert, formatted_cert, &formatted_cert_len);
    if (tmp.code != YERR_SUCCESS) {
        *verify_result = UNIFY_ERROR_CODE(tmp.code);
        return result;
    }

    /* verify cert */
    result = sm2_verify(hex_public, formatted_cert, formatted_cert_len,
                        sig, sig_len, verify_result);
    return result;
}
