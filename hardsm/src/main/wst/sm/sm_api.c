#include "../proto/protobuf-c.h"
#include "../proto/sm.pb-c.h"
#include "../include/util.h"
#include "../include/sm.h"


static void fail_response(Response *response, int code, const char *msg) {
    response->code = UNIFY_ERROR_CODE(code);
    response->has_code = true;
    response->msg = (char *) GET_ERROR_STR(code, msg);
    response->details = "";
}

int init_login(const char *pin_code, uint8_t *out) {
    int packlen = 0;
    Response response = RESPONSE__INIT;

    Result result = device_init(pin_code);
    if (result.code != YERR_SUCCESS) goto fail;

    response.code = YERR_SUCCESS;
    response.has_code = true;
    response.msg = SUCCESS_MSG;
    response.details = "";
    packlen = response__pack(&response, out);
    return packlen;

fail:
    device_finalize();
    fail_response(&response, result.code, result.msg);
    packlen = response__pack(&response, out);
    return packlen;
}


int finalize(uint8_t *out) {
    Result result = init_result();
    Response response = RESPONSE__INIT;
    int packlen = 0;

    result = device_finalize();

    if (SM_ERR_FREE != result.code) goto fail;

    response.code = YERR_SUCCESS;
    response.has_code = true;
    response.msg = SUCCESS_MSG;
    response.details = "";
    packlen = response__pack(&response, out);

    return packlen;

fail:
    fail_response(&response, result.code, result.msg);
    packlen = response__pack(&response, out);
    return packlen;
}

int sign_st(const char *b64_signature, const char *hex_private, uint8_t *out) {
    if (NULL == b64_signature || NULL == hex_private || NULL == out)
        return YERR_PARAM_ERROR;

    Result result = init_result();
    Response response = RESPONSE__INIT;
    StrValue sig = STR_VALUE__INIT;
    int packlen = 0;

    /* compose signature fields */
    Signature signature;
    memset(&signature, 0, sizeof(signature));
    result = load_signature(b64_signature, &signature);
    if (result.code != YERR_SUCCESS) goto fail;

    /* sign */
    char b64_signature_result[MAX_SIGNATURE_LEN + 1] = {0};
    result = sign_signature(&signature, hex_private, b64_signature_result);
    if (SM_ERR_FREE != result.code) goto fail;

    response.data_case = RESPONSE__DATA_STR_VALUE;
    response.str_value = &sig;
    response.code = YERR_SUCCESS;
    response.has_code = true;
    response.msg = SUCCESS_MSG;
    response.details = "";
    sig.value = b64_signature_result;

    packlen = response__pack(&response, out);
    return packlen;

fail:
    fail_response(&response, result.code, result.msg);
    packlen = response__pack(&response, out);
    return packlen;
}


int verify_st(const char *b64_sig, uint8_t *out) {
    if (NULL == b64_sig || NULL == out) return YERR_PARAM_ERROR;

    Result result;
    Response response = RESPONSE__INIT;
    IntValue verify_result = INT_VALUE__INIT;
    int is_valid = 0;

    /* unpack signature */
    Signature signature;
    memset(&signature, 0, sizeof(signature));
    result = load_signature(b64_sig, &signature);
     if (result.code != YERR_SUCCESS) {
        is_valid = UNIFY_ERROR_CODE(result.code);
        goto end;
    }

    /* verify signature */
    // load cert and get public key
    MinimalCert minimal_cert;
    memset(&minimal_cert, 0, sizeof(minimal_cert));
    result = load_cert(signature.ct, &minimal_cert);
    if (result.code != YERR_SUCCESS) {
        is_valid = UNIFY_ERROR_CODE(result.code);
        goto end;
    }

    // verify
    result = verify_signature(b64_sig, minimal_cert.pk, &is_valid);
    if (result.code != YERR_SUCCESS) {
        goto fail;
    } else {
        goto end;
    }


end:
    response.code = YERR_SUCCESS;
    response.has_code = true;
    response.msg = SUCCESS_MSG;
    response.details = "";
    response.data_case = RESPONSE__DATA_INT_VALUE;
    response.int_value = &verify_result;

    verify_result.value = is_valid;
    verify_result.has_value = true;

    int packlen = response__pack(&response, out);
    return packlen;


fail:
    fail_response(&response, result.code, result.msg);
    packlen = response__pack(&response, out);
    return packlen;
}


int sign_data(const char *data, int data_len,
              const char *hex_private, uint8_t *out) {
    if (NULL == data || NULL == hex_private || NULL == out)
        return YERR_PARAM_ERROR;

    Result result = init_result();
    Response response = RESPONSE__INIT;
    StrValue sig = STR_VALUE__INIT;
    int packlen = 0;

    /* sign */
    char sig_value[MAX_SIGVALUE_LENGTH + 1] = {0};
    int sig_value_len = 0;
    result = sm2_sign(hex_private, data, data_len,
                      sig_value, &sig_value_len);
    if (result.code != YERR_SUCCESS) goto fail;
    // turn sig value to hex format
    char hex_sigvalue[MAX_SIGVALUE_LENGTH + 1] = {0};
    to_hex(hex_sigvalue, sizeof(hex_sigvalue), sig_value, sig_value_len);

    response.data_case = RESPONSE__DATA_STR_VALUE;
    response.str_value = &sig;
    response.code = YERR_SUCCESS;
    response.has_code = true;
    response.msg = SUCCESS_MSG;
    response.details = "";
    sig.value = hex_sigvalue;

    packlen = response__pack(&response, out);
    return packlen;

fail:
    fail_response(&response, result.code, result.msg);
    packlen = response__pack(&response, out);
    return packlen;
}


int verify_data(const char *plain_data, int plain_data_len,
                const char *signed_data, const char *hex_public, uint8_t *out) {
    if (NULL == plain_data || NULL == signed_data ||
        NULL == hex_public || NULL == out)
        return YERR_PARAM_ERROR;

    Result result;
    Response response = RESPONSE__INIT;
    IntValue verify_result = INT_VALUE__INIT;
    int is_valid = 0;

    char sig[MAX_SIGNATURE_LEN + 1] = {0};
    int sig_len;
    int ret = from_hex(sig, &sig_len, signed_data);
    if (ret != YERR_SUCCESS) {
        is_valid = UNIFY_ERROR_CODE(ret);
        goto end;
    }

    // verify
    result = sm2_verify(hex_public, plain_data, plain_data_len, sig,
                        sig_len, &is_valid);
    if (result.code != YERR_SUCCESS) {
        goto fail;
    } else {
        goto end;
    }


end:
    response.code = YERR_SUCCESS;
    response.has_code = true;
    response.msg = SUCCESS_MSG;
    response.details = "";
    response.data_case = RESPONSE__DATA_INT_VALUE;
    response.int_value = &verify_result;

    verify_result.value = is_valid;
    verify_result.has_value = true;

    int packlen = response__pack(&response, out);
    return packlen;


fail:
    fail_response(&response, result.code, result.msg);
    packlen = response__pack(&response, out);
    return packlen;
}



int gen_key(const char *start_date, const char *end_date, uint8_t *out) {
    if (NULL == start_date || NULL == end_date || NULL == out) {
        return YERR_PARAM_ERROR;
    }

    Result result = init_result();
    Response response = RESPONSE__INIT;
    KeyPair key_pair = KEY_PAIR__INIT;
    int packlen = 0;

    char public_key[MAX_KEY_LEN] = {0};
    char private_key[MAX_KEY_LEN] = {0};

    result = generate_ecc_key(start_date, end_date, public_key,
                              sizeof(public_key), private_key,
                              sizeof(private_key));
    if (result.code != YERR_SUCCESS) goto fail;

    response.data_case = RESPONSE__DATA_KEY_PAIR;
    response.key_pair = &key_pair;
    response.code = YERR_SUCCESS;
    response.has_code = true;
    response.msg = SUCCESS_MSG;
    response.details = "";
    key_pair.public_key = public_key;
    key_pair.private_key = private_key;

    packlen = response__pack(&response, out);
    return packlen;


fail:
    fail_response(&response, result.code, result.msg);
    packlen = response__pack(&response, out);
    return packlen;
}


int sign_ct(const char *b64_cert, const char *hex_private, uint8_t *out) {
    if (NULL == b64_cert || NULL == hex_private || NULL == out)
        return YERR_PARAM_ERROR;

    Result result = init_result();
    Response response = RESPONSE__INIT;
    StrValue sig = STR_VALUE__INIT;
    int packlen = 0;

    /* compose cert fields */
    MinimalCert minimal_cert;
    memset(&minimal_cert, 0, sizeof(minimal_cert));
    result = load_cert(b64_cert, &minimal_cert);
    if (result.code != YERR_SUCCESS) goto fail;

    /* sign */
    char b64_cert_result[MAX_CERT_LEN + 1] = {0};
    result = sign_cert(&minimal_cert, hex_private, b64_cert_result);
    if (SM_ERR_FREE != result.code) goto fail;

    response.data_case = RESPONSE__DATA_STR_VALUE;
    response.str_value = &sig;
    response.code = YERR_SUCCESS;
    response.has_code = true;
    response.msg = SUCCESS_MSG;
    response.details = "";
    sig.value = b64_cert_result;

    packlen = response__pack(&response, out);
    return packlen;

fail:
    fail_response(&response, result.code, result.msg);
    packlen = response__pack(&response, out);
    return packlen;
}


int verify_ct(const char *b64_cert, uint8_t *out) {
    if (NULL == b64_cert || NULL == out) return YERR_PARAM_ERROR;

    Result result;
    Response response = RESPONSE__INIT;
    IntValue verify_result = INT_VALUE__INIT;
    int is_valid = 0;

    /* unpack cert */
    MinimalCert minimal_cert;
    memset(&minimal_cert, 0, sizeof(minimal_cert));
    result = load_cert(b64_cert, &minimal_cert);
    if (result.code != YERR_SUCCESS) {
        is_valid = UNIFY_ERROR_CODE(result.code);
        goto end;
    }

    // verify
    result = verify_cert(b64_cert, minimal_cert.pk, &is_valid);
    if (result.code != YERR_SUCCESS) {
        goto fail;
    } else {
        goto end;
    }


end:
    response.code = YERR_SUCCESS;
    response.has_code = true;
    response.msg = SUCCESS_MSG;
    response.details = "";
    response.data_case = RESPONSE__DATA_INT_VALUE;
    response.int_value = &verify_result;

    verify_result.value = is_valid;
    verify_result.has_value = true;

    int packlen = response__pack(&response, out);
    return packlen;


fail:
    fail_response(&response, result.code, result.msg);
    packlen = response__pack(&response, out);
    return packlen;
}

int sm3_hash(const char *data, int data_len, uint8_t *out) {
    if (NULL == data || NULL == out)
        return YERR_PARAM_ERROR;

    Result result = init_result();
    Response response = RESPONSE__INIT;
    StrValue sig = STR_VALUE__INIT;
    int packlen = 0;

    /* hash */
    char digest[MAX_DIGEST_LEN + 1] = {0};
    int digest_len = sizeof(digest);
    result = sm3_hash_data(data, data_len, digest, &digest_len);
    if (SM_ERR_FREE != result.code) goto fail;

    char hex_digest[MAX_DIGEST_LEN + 1] = {0};
    to_hex(hex_digest, sizeof(hex_digest), digest, digest_len);

    response.data_case = RESPONSE__DATA_STR_VALUE;
    response.str_value = &sig;
    response.code = YERR_SUCCESS;
    response.has_code = true;
    response.msg = SUCCESS_MSG;
    response.details = "";
    sig.value = hex_digest;

    packlen = response__pack(&response, out);
    return packlen;

fail:
    fail_response(&response, result.code, result.msg);
    packlen = response__pack(&response, out);
    return packlen;
}
