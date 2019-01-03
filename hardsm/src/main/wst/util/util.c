#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>
#include "../include/util.h"


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
    }
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

static const char hex_table[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};


bool is_hex(const char *str) {
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


int from_hex(char *buf, int *len, const char *hex_str) {
    assert(NULL != hex_str);

    if (!is_hex(hex_str)) return YERR_FORMAT_ERROR;

    int i;
    for (i = 0; i < strlen(hex_str); i++) {
        char c = hex_str[i];
        c = tolower(c);
        int val = c > '9'? 10 + c - 'a' : c - '0';

        if (i & 0x01) {
            *buf |= (val);
            buf++;
        } else {
            *buf = (val << 4);
        }
    }
    *len = strlen(hex_str) / 2;

    return YERR_SUCCESS;
}


void print_log(int level, const char* filename, const char* func_name,
               int line, const char* fmt, ...) {
    char* pc_level;
    switch (level) {
        case LOG_LEVEL_DEBUG:
            pc_level = "[DEBUG]";
            break;
        case LOG_LEVEL_INFO:
            pc_level = "[INFO]";
            break;
        case LOG_LEVEL_WARN:
            pc_level = "[WARNING]";
            break;
        case LOG_LEVEL_ERROR:
            pc_level = "[ERROR]";
            break;
        default:
            pc_level = "INFO";
            break;
    }

    time_t rawtime;
    time(&rawtime);

    fprintf(stderr, "%s %s, %s, %d | %s", pc_level, filename,
            func_name, line, ctime(&rawtime));
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "\t");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    fflush(stderr);
}
