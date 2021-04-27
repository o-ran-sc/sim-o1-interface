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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>


#include <core/framework.h>

static int instances = 0;
static FILE* logfile = 0;

static int file_no = 0;
static int line_no = 0;
static const char *filename;

static char *extract_format(const char *format);

void log_init(const char *logfilename) {
    assert(instances == 0);
    instances++;

    logfile = fopen(logfilename, "w");

    assert(logfile);
    file_no = 0;
    line_no = 0;
    filename = logfilename;
}

void log__message(char const * const fname, uint32_t location, int verbose_level, const char *format, ...) {
    if(verbose_level >= 0) {
        line_no++;
        if(line_no >= 5000) {
            fclose(logfile);

            file_no++;
            char logfilename[512];
            sprintf(logfilename, "%s.%d", filename, file_no);
            logfile = fopen(logfilename, "w");
            line_no = 0;
        }
    }

    va_list arg;

    char *verbose_file = 0;
    int free_verbose_file = 0;

    char *verbose_screen = 0;
    int free_verbose_screen = 0;

    if(verbose_level < 0) {
        //when verbose negative, treat as add (no filename, line, time, etc)
        verbose_level = -verbose_level;
        verbose_file = (char *)format;
        verbose_screen = (char *)format;
    }
    else {
        //extract just the filename, no path
        const char *filename = fname + strlen(fname) - 1;
        while((filename != fname) && (*filename != '/')) {
            filename--;
        }
        if(*filename == '/') {
            filename++;
        }

        time_t t = time(NULL);
        struct tm tm = *localtime(&t);

        asprintf(&verbose_file, "[%d-%02d-%02d|%02d:%02d:%02d|%s:%u] %s", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, filename, location, format);
        if(verbose_file == 0) {
            verbose_file = (char *)format;
        }
        else {
            free_verbose_file = 1;
        }

        if(verbose_level != 0) {
            asprintf(&verbose_screen, "[%d-%02d-%02d|%02d:%02d:%02d] %s", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, format);
        }
        else {
            verbose_screen = strdup(verbose_file);
        }

        if(verbose_screen == 0) {
            verbose_screen = (char *)format;
        }
        else {
            free_verbose_screen = 1;
        }
    }
    
    //log to file in an uncolored format (simple format)
    va_start(arg, format);
    char *simple_format = extract_format(verbose_file);
    vfprintf(logfile, simple_format, arg);

    if(simple_format != verbose_file) {
        free(simple_format);
    }
    va_end(arg);
    fflush(logfile);

    if(free_verbose_file) {
        free(verbose_file);
    }

    if(verbose_level <= framework_arguments.verbosity_level) {
        
        if(verbose_level == 0) {      
            fprintf(stderr, LOG_COLOR_BOLD_RED);
            va_start(arg, format);
            vfprintf(stderr, verbose_screen, arg);
            va_end(arg);
            fprintf(stderr, LOG_COLOR_RESET);

            fprintf(stdout, LOG_COLOR_BOLD_RED);
        }

        va_start(arg, format);
        vfprintf(stdout, verbose_screen, arg);
        va_end(arg);

        if(verbose_level == 0) {
            fprintf(stdout, LOG_COLOR_RESET);
        }
    }

    if(free_verbose_screen) {
        free(verbose_screen);
    }
}

void log_close(void) {
    fclose(logfile);
    instances--;
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

void log_redirect_stderr(const char *stderrfilename) {
    remove(stderrfilename);
    int stderr_fd = open(stderrfilename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    dup2(stderr_fd, STDERR_FILENO);
    close(stderr_fd);
}
