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


#define YERR_SUCCESS                0
#define YERR_FORMAT_ERROR           501
#define NO_DEVICE_ERROR             601
#define DEVICE_CLOSE_ERROR          602
#define INDEX_OUTOF_BOUND           603
#define DEVICE_NOT_OPENED           604
#define PIPE_NOT_OPENED             605
#define PIPE_RESOURCE_EXCEEDED      606
#define BUFSIZE_TOO_SMALL           607
#define NEED_LOGIN                  608
#define RANDOM_LEN_OUTOF_BOUND      609
#define KEY_LENGTH_INVALID          610
#define IV_LENGTH_INVALID           611
#define BLOCK_LENGTH_INVALID        612
#define DATA_TOO_LONG               613
#define PINCODE_LEN_ERROR           614


enum LOG_LEVEL {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
};

void print_log(int level, const char* filename, const char* func_name, int line, const char* fmt, ...);

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

/* YYYYMMDDhhmmss */
void get_localtime(char *time_str, int len);

/* yyyymmdd */
void date_today(char *date, int len);

/* yyyymmdd compressed in 4 bytes */
void compress_date(const char *date, char *compressed_date, int *len);

/* decompress date to yyyymmdd */
void decompress_date(const char *compressed_date, int compressed_date_len, char *date, int date_len);

void to_hex(char *buf, int buf_len, const char *data, int data_len);

int from_hex(char *buf, int *len, const char *hexdata);

bool is_hex(const char *str);

void init_error_string();

char *get_error_string(int code);

void print_error(int code);

void update_error_code(int *codes, int *codes_len, int max_codes_len, int code);

#ifdef __cplusplus
}
#endif

#endif
