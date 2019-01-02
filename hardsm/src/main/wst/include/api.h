/* sm shared library protobuf api */

int init_login(const char *pin_code, uint8_t *out);

int finalize(uint8_t *out);

int sign_st(const char *b64_signature, const char *hex_private, uint8_t *out);

int verify_st(const char *b64_sig, uint8_t *out);

int sign_ct(const char *b64_cert, const char *hex_private, uint8_t *out);

int verify_ct(const char *b64_cert, uint8_t *out);

int sign_data(const char *data, int data_len, 
              const char *hex_private, uint8_t *out);

int verify_data(const char *plain_data, int plain_data_len, 
                const char *signed_data, const char *hex_public, uint8_t *out);

int gen_key(const char *start_date, const char *end_date, uint8_t *out);

int sm3_hash(const char *data, int data_len, uint8_t *out);
