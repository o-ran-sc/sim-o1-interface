/*************************************************************************
*
* Copyright 2020 highstreet technologies GmbH and others
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
***************************************************************************/

#define _GNU_SOURCE

#include "log_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>
#include <assert.h>

#include <core/framework.h>

static int instances = 0;
static int errors = 0;
static FILE* logfile = 0;

static char *extract_format(const char *format);

void log_init(const char *logfilename) {
    assert(instances == 0);
    instances++;

    logfile = fopen(logfilename, "w");

    assert(logfile);

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    fprintf(logfile, "started at: %d-%02d-%02d %02d:%02d:%02d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    fprintf(stdout, LOG_COLOR_BOLD_RED"started at: %d-%02d-%02d %02d:%02d:%02d\n"LOG_COLOR_RESET, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

void log__message(char const * const filename, uint32_t location, const int verbose_level, const char *format, ...) {
    va_list arg;

    char *format2 = 0;
    asprintf(&format2, "[%s:%u] %s", filename, location, format);
    if(format2 == 0) {
        fprintf(stderr, LOG_COLOR_BOLD_RED"bad malloc in log system\n"LOG_COLOR_RESET);
        format2 = (char *)format;
    }

    va_start(arg, format);
    char *new_format = extract_format(format2);
    vfprintf(logfile, new_format, arg);

    if(new_format != format2) {
        free(new_format);
    }

    if(format2 != format) {
        free(format2);
    }
    fflush(logfile);
    va_end(arg);

    if(verbose_level <= framework_arguments.verbosity_level) {
        va_start(arg, format);
        vfprintf(stdout, format, arg);
        va_end(arg);
    }
}

void log__error(char const * const function, uint32_t location, const char *format, ...) {
    va_list arg;
    bool has_newline = false;
    if(format[strlen(format) - 1] == '\n') {
        has_newline = true;
    }

    errors++;
    char *new_format = extract_format(format);
    fprintf(logfile, "[error in %s():%d] ", function, location);
    va_start(arg, format);
    vfprintf(logfile, new_format, arg);
    if(new_format != format) {
        free(new_format);
    }
    if(!has_newline) {
        fprintf(logfile, "\n");
    }
    fflush(logfile);
    va_end(arg);

    fprintf(stderr, "["LOG_COLOR_RED"error in "LOG_COLOR_BOLD_RED"%s()"LOG_COLOR_RED":"LOG_COLOR_BOLD_CYAN"%d"LOG_COLOR_RESET"] ", function, location);
    va_start(arg, format);
    vfprintf(stderr, format, arg);
    if(!has_newline) {
        fprintf(stderr, "\n");
    }
    va_end(arg);
}

void log_close(void) {
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    fprintf(logfile, "finished at: %d-%02d-%02d %02d:%02d:%02d\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    fclose(logfile);

    if(errors) {
        fprintf(stderr, "-------- !!!!!! ERRORS WERE PRESENT, CHECK ERROR FILE !!!!!! ------------\n\n\n\n");
    }
}

static char *extract_format(const char *format) {
    assert(format);

    int l = strlen(format);
    char *ret = (char *)malloc(sizeof(char) * (l + 1));
    if(ret == 0) {
        fprintf(stderr, LOG_COLOR_BOLD_RED"bad malloc in log system\n"LOG_COLOR_RESET);
        return (char *)format;
    }

    int s = 0;
    int d = 0;
    bool in_escape = false;

    while(s < l) {
        if(!in_escape) {
            //escape char
            if(format[s] == 27) {
                in_escape = true;
                s++;
            }
        }
        else {
            if(format[s] == 'm') {
                in_escape = false;
                s++;
            }
        }


        if(!in_escape) {
            ret[d++] = format[s];
        }

        s++;
    }

    ret[d] = 0;
  
    return ret;
}
