#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>
#include "../include/sm_api.h"
#include "../proto/sm.pb-c.h"
#include "../include/util.h"


Result handle_result(Result result) {
    Result new_result;
    new_result.code = UNIFY_ERROR_CODE(result.code);
    strcpy(new_result.msg, GET_ERROR_STR(result.code, result.msg));
    return new_result;
}


/* YYYYMMDDhhmmss */
void get_localtime(char *time_str, int len) {
    assert(len > 14);
    struct tm   when;
    time_t      now;

    time( &now );
    when = *localtime( &now );
    snprintf(time_str, len, "%04d%02d%02d%02d%02d%02d",
             when.tm_year + 1900, when.tm_mon + 1, when.tm_mday,
             when.tm_hour, when.tm_min, when.tm_sec);
}

void date_today(char *date, int len) {
    assert(len > 8);
    struct tm   when;
    time_t      now;

    time( &now );
    when = *localtime( &now );
    snprintf(date, len, "%04d%02d%02d", when.tm_year + 1900,
             when.tm_mon + 1, when.tm_mday);
}

void compress_date(const char *date, char *compressed_date, int *len) {
    assert(*len >= strlen(date) / 2);
    *len = strlen(date) / 2;

    int i;
    for (i = 0; i < strlen(date); i += 2) {
        compressed_date[i/2] = (((date[i] - 0x30) << 4) | (date[i + 1] - 0x30));
    } // for
}

void decompress_date(const char *compressed_date, int compressed_date_len,
                     char *date, int date_len) {
    assert(compressed_date_len * 2 + 1 <= date_len);

    int i;
    for (i = 0; i < compressed_date_len; i++) {
        char c = compressed_date[i];
        *date = ((c & 0xf0) >> 4) + 0x30;
        date++;
        *date = (c & 0x0f) + 0x30;
        date++;
    }
    *date = 0;
}

Result init_result() {
    Result result;
    result.code = YERR_SUCCESS;
    strncpy(result.msg, SUCCESS_MSG, sizeof(result.msg));
    return result;
}


int count_chips(const char *string, char separator) {
    assert(NULL != string);

    int count = 1;
    while (*string != 0) {
        if (*string == separator) count++;
        string++;
    }

    return count;
}


const char *next_chip(const char *string, char separator, char *chip) {
    if (NULL == string) return NULL;

    const char *cursor = string;
    while (*cursor != 0) {
        if (*cursor == separator) {
            strncpy(chip, string, cursor - string);
            return cursor + 1;
        } else {
            cursor++;
        }
    }
    strncpy(chip, string, cursor - string);

    if (*cursor == 0) return NULL;
    return cursor;
}


static const char hex_table[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};


bool ishex(const char *str) {
    if (NULL == str) return true;
    if (strlen(str) & 0x01) return false;

    int i;
    for (i = 0; i < strlen(str); i++)
    {
        char c = str[i];
        c = tolower(c);
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}


void to_hex(char *buf, int buf_len, const char *data, int data_len) {
    assert(buf_len >= data_len * 2 + 1);

    int i;
    for (i = 0; i < data_len; i++) {
        *buf = hex_table[(data[i] >> 4) & 0x0F];
        buf++;
        *buf = hex_table[data[i] & 0x0F];
        buf++;
    }
    *buf = '\0';
}


int from_hex(char *buf, int *len, const char *hexdata) {
    assert(NULL != hexdata);
    int err = YERR_SUCCESS;

    if (!ishex(hexdata)) return YERR_FORMAT_ERROR;

    int i;
    for (i = 0; i < strlen(hexdata); i++) {
        char c = hexdata[i];
        c = tolower(c);
        int val = c > '9'? 10 + c - 'a' : c - '0';

        if (i & 0x01) {
            *buf |= (val);
            buf++;
        } else {
            *buf = (val << 4);
        }
    }
    *len = strlen(hexdata) / 2;
    return err;
}


void print_log(int level, const char* filename, const char* func_name,
               int line, const char* fmt, ...) {
    char* pclevel;
    switch (level) {
        case LOG_LEVEL_DEBUG:
            pclevel = "[DEBUG]";
            break;
        case LOG_LEVEL_INFO:
            pclevel = "[INFO]";
            break;
        case LOG_LEVEL_WARN:
            pclevel = "[WARNING]";
            break;
        case LOG_LEVEL_ERROR:
            pclevel = "[ERROR]";
            break;
        default:
            pclevel = "INFO";
            break;
    }

    time_t rawtime;
    time(&rawtime);

    fprintf(stderr, "%s %s, %s, %d | %s", pclevel, filename,
            func_name, line, ctime(&rawtime));
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "\t");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    fflush(stderr);
}
