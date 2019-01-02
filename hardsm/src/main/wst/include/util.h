#ifndef UTIL_H
#define UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

typedef int bool;

/* error code: negative for native error code, positive for sm error */
#define YERR_SUCCESS                0
#define YERR_UNKNOWN_ERROR          -1
#define YERR_SERVER_ERROR           -2

#define YERR_PARAM_ERROR            -101
#define YERR_FORMAT_ERROR           -102
#define YERR_UNSUPPORT_ERROR        -103

#define YERR_TOO_FREQUENT_ERROR     -111
#define YERR_RESTRICTION_ERROR      -112
#define YERR_PERMISSION_DENIED      -113

#define YERR_NODATA_ERROR           -121
#define YERR_DATA_CONFICT_ERROR     -122
#define YERR_DATA_EXCESS            -123

#define YERR_NEED_LOGIN_ERROR       -131
#define YERR_TOKEN_EXPIRED_ERROR    -132
#define YERR_KICKED_OUT_ERROR       -133
#define YERR_ACCOUNT_OR_PASS_ERROR  -134
#define YERR_ACCOUNT_OR_PINCODE_ERROR  -135
#define YERR_PASSWORD_ERROR         -136
#define YERR_PINCODE_ERROR          -137

#define YERR_SERVER_UNAVAILABLE     -1001
#define YERR_VERIFY_DENIED          -1002
#define YERR_NOT_FULL_CONFIGURED    -1007
#define YERR_FAILED_CONNECT_REDIS   -1008
#define YERR_REDIS_ERROR            -1009
#define YERR_SEAL_STATUS_UNAVAILABLE -1010
#define YERR_BEYOND_SEAL_VALID_TIME -1012
#define YERR_MISS_SIGNATURE         -1013

#define SUCCESS_MSG     "success"


// sm error 10000+
#define SM_ERR_SECTION      10000
#define NO_DEVICE_ERROR     301
// failed self inspection 400+
#define UNIFY_ERROR_CODE(code) (code <= 0? (code * -1) : (SM_ERR_SECTION + code))
// 0 ~ 300 is the sm cipher error code range
#define GET_ERROR_STR(code, msg) (code < 0 || code > 300? msg : SM_GetErrorString(code, false))


typedef struct {
    int code;
    char msg[128 + 1];
} Result;

enum LOG_LEVEL {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
};

void print_log(int level, const char* filename, 
               const char* func_name, int line, const char* fmt, ...);

#define LOG_DEBUG(...) \
    print_log(LOG_LEVEL_DEBUG, __FILE__, __func__, __LINE__, ##__VA_ARGS__)

#define LOG_INFO(...) \
    print_log(LOG_LEVEL_INFO, __FILE__, __func__, __LINE__, ##__VA_ARGS__)

#define LOG_WARN(...) \
    print_log(LOG_LEVEL_WARN, __FILE__, __func__, __LINE__, ##__VA_ARGS__)

#define LOG_ERROR(...) \
    print_log(LOG_LEVEL_ERROR, __FILE__, __func__, __LINE__, ##__VA_ARGS__)

#define LOG_FATAL(...) \
    print_log(LOG_LEVEL_FATAL, __FILE__, __func__, __LINE__, ##__VA_ARGS__)

Result init_result();

/* YYYYMMDDhhmmss */
void get_localtime(char *time_str, int len);

/* yyyymmdd */
void date_today(char *date, int len);

/* yyyymmdd compressed in 4 bytes */
void compress_date(const char *date, char *compressed_date, int *len);

/* decompress date to yyyymmdd */
void decompress_date(const char *compressed_date, int compressed_date_len, 
                     char *date, int date_len);

int count_chips(const char *string, char separator);

const char *next_chip(const char *string, char separator, char *chip);

void to_hex(char *buf, int buf_len, const char *data, int data_len);

int from_hex(char *buf, int *len, const char *hexdata);

bool ishex(const char *str);

#ifdef __cplusplus
}
#endif

#endif
