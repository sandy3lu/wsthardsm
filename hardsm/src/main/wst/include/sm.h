#ifndef SM__H
#define SM__H

#ifdef __cplusplus
extern "C" {
#endif

#include "sm_inn_type.h"
#include "sm_api_type.h"
#include "sm_algo.h"
#include "sm_api.h"

// #define MOCK_MODE   1
#define MOCK ({if (MOCK_MODE) {Result result = init_result(); return result;}})

typedef int bool;
#define true 1
#define false 0

#define MAX_SIGNATURE_LEN   4096
#define MAX_KEY_LEN         1024
#define MAX_DIGEST_LEN      128
#define DATE_LEN            8
#define KEY_ATTR_LEN        128
#define MAX_CERT_LEN        2048
#define MAX_SIGVALUE_LENGTH 1024
#define MAX_CERT_KEY_LEN    32
#define MAX_SIG_KEY_LEN     32

#define YJ_MANUFACTURE  "westone"
#define YJ_PUBLIC_KEY   "pub"
#define YJ_PRIVATE_KEY  "pri"
#define YJ_ECC          "ecc"
#define YJ_RSA          "rsa"
#define YJ_SM1_ECB      "sm1_ecb"
#define YJ_SM1_CBC      "sm1_cbc"
#define YJ_SM1_MAC      "sm1_mac"
#define YJ_SM3_SCH      "sm3_sch"

#define CERT_KEY_VS  "vs"
#define CERT_KEY_PK  "pk"
#define CERT_KEY_PD  "pd"
#define CERT_KEY_DA  "da"
#define CERT_KEY_SG  "sg"
#define CERT_KEY_SD  "sd"
#define CERT_KEY_ED  "ed"
#define CERT_KEY_LV  "lv"
#define CERT_KEY_TS  "ts"

#define CERT_KEY_MF  "mf"
#define CERT_KEY_AG  "ag"
#define CERT_KEY_BT  "bt"
#define CERT_KEY_FG  "fg"

#define CERT_KEY_CN  "cn"
#define CERT_KEY_IU  "iu"
#define CERT_KEY_SC  "sc"
#define CERT_KEY_SN  "sn"
#define CERT_KEY_ST  "st"
#define CERT_KEY_UN  "un"
#define CERT_KEY_ID  "id"


#define CERT_KEY_VS_BIT  1
#define CERT_KEY_PK_BIT  (1 << 1)
#define CERT_KEY_PD_BIT  (1 << 2)
#define CERT_KEY_DA_BIT  (1 << 3)
#define CERT_KEY_SG_BIT  (1 << 4)
#define CERT_KEY_SD_BIT  (1 << 5)
#define CERT_KEY_ED_BIT  (1 << 6)
#define CERT_KEY_LV_BIT  (1 << 7)
#define CERT_KEY_TS_BIT  (1 << 8)

#define CERT_KEY_MF_BIT  (1 << 9)
#define CERT_KEY_AG_BIT  (1 << 10)
#define CERT_KEY_BT_BIT  (1 << 11)
#define CERT_KEY_FG_BIT  (1 << 12)

#define CERT_KEY_CN_BIT  (1 << 13)
#define CERT_KEY_IU_BIT  (1 << 14)
#define CERT_KEY_SC_BIT  (1 << 15)
#define CERT_KEY_SN_BIT  (1 << 16)
#define CERT_KEY_ST_BIT  (1 << 17)
#define CERT_KEY_UN_BIT  (1 << 18)
#define CERT_KEY_ID_BIT  (1 << 19)
#define CERT_KEY_ALL_BITS 1048559  // exclude CERT_KEY_SG_BIT


/* structure for cert */
typedef struct {
    char vs[64 + 1];     // version
    char pk[128 + 1];   // public key
    char pd[64 + 1];    // parent cert digest, hex format
    char da[64 + 1];    // digest algorithm of 'pd'
    char sg[MAX_SIGVALUE_LENGTH + 1];   // signature of this cert
    char sd[64 + 1];    // start date, eg: 20180518
    char ed[64 + 1];    // end date, eg: 20201231
    char lv[64 + 1];     // cert level, 0 for root cert
    char ts[64 + 1];    // timestamp

    char mf[64 + 1];    // manufactor, by which device the public key generated
    char ag[64 + 1];    // algorithm, algorithm for generating public key
    char bt[64 + 1];     // bits, how many bits of the key
    char fg[64 + 1];     // flags, various in different device

    char cn[64 + 1];     // county
    char iu[64 + 1];    // issuer, yunjingit
    char sc[64 + 1];    // seal code
    char sn[64 + 1];    // seal name
    char st[64 + 1];    // seal type
    char un[64 + 1];    // use unit code
    char id[64 + 1];    // identify no
} MinimalCert;
// lexicographical order
// ['ag', 'bt', 'cn', 'da', 'ed', 'fg', 'id', 'iu', 'lv', 'mf',
//  'pd', 'pk', 'sc', 'sd', 'sn', 'st', 'ts', 'un', 'vs', 'sg']


#define SIG_KEY_VS  "vs"
#define SIG_KEY_DH  "dh"
#define SIG_KEY_CS  "cs"
#define SIG_KEY_TS  "ts"
#define SIG_KEY_MC  "mc"
#define SIG_KEY_CT  "ct"
#define SIG_KEY_SG  "sg"


#define SIG_KEY_VS_BIT  1
#define SIG_KEY_DH_BIT  (1 << 1)
#define SIG_KEY_CS_BIT  (1 << 2)
#define SIG_KEY_TS_BIT  (1 << 3)
#define SIG_KEY_MC_BIT  (1 << 4)
#define SIG_KEY_CT_BIT  (1 << 5)
#define SIG_KEY_SG_BIT  (1 << 6)
#define SIG_KEY_ALL_BITS 59  // exclude SIG_KEY_CS_BIT and SIG_KEY_SG_BIT


typedef struct {
    char vs[64 + 1];
    char dh[64 + 1];
    char cs[128 + 1];
    char ts[64 + 1];
    char mc[64 + 1];
    char ct[MAX_CERT_LEN + 1];
    char sg[MAX_SIGVALUE_LENGTH + 1];
} Signature;

#define SIGNATURE_VERSION   "01"

// key attr: westone-ecc-256-450-20100425-20200425-sm1_ecb
// signature attr: westone-ecc-256-sm3_sch_256

typedef struct {
    int device_type;
    char api_version[32];
    int device_count;
    int mechanism_list[32];
    int mechanism_len;
    SM_DEVICE_INFO sm_device_info;
} DeviceInfo;


typedef struct {
    char manufacturer[16 + 1];
    char type[8 + 1];
    int bits;
    int flag;
    char start_date[16 + 1];
    char end_date[16 + 1];
    char safety[16 + 1];
} KeyAttr;


typedef struct {
    SM_DEVICE_HANDLE h_device;
    SM_PIPE_HANDLE   h_pipe;
    SM_KEY_HANDLE    h_auth_key;
    DeviceInfo device_info;
} Handles;


Result handle_result(Result result);

Result device_init(const char *pin_code);

Result device_finalize();

Result generate_ecc_key(const char *start_date, const char *end_date,
                        char *hex_public, int hex_public_len, char *hex_private,
                        int hex_private_len);

Result gen_signature(Signature *signature, char *b64str);

Result load_signature(const char *b64_sig, Signature *signature);

Result sign_signature(Signature *signature, const char *hex_private,
                      OUT char *b64_signature);

Result verify_signature(const char *b64_sig, const char *hex_public,
                        int *verify_result);

Result gen_cert(MinimalCert *minimal_cert, char *b64str);

Result load_cert(const char *b64_cert, MinimalCert *minimal_cert);

Result sign_cert(MinimalCert *minimal_cert, const char *hex_private,
                OUT char *b64_cert);

Result verify_cert(const char *b64_cert, const char *hex_public,
                   int *verify_result);

Result generate_ecc_key(const char *start_date, const char *end_date,
                        char *hex_public, int hex_public_len, char *hex_private,
                        int hex_private_len);

Result sm3_hash_data(const char *data, int data_len,
                     char *digest, int *digest_len);

Result sm2_sign(const char *hex_private, const char *plain_data,
                int plain_data_len, char *signature, int *signature_len);

Result sm2_verify(const char *hex_public, const char *plain_data,
                  int plain_data_len, const char *signature, int signature_len,
                  int *verify_result);


#ifdef __cplusplus
}
#endif

#endif
