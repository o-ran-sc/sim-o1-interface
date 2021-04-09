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

#pragma once

#include <string.h>
#include <stdint.h>

#define LOG_COLOR_RESET         "\033[0m"
#define LOG_COLOR_RED           "\033[0;31m"
#define LOG_COLOR_BOLD_RED      "\033[1;31m"
#define LOG_COLOR_GREEN         "\033[0;32m"
#define LOG_COLOR_BOLD_GREEN    "\033[1;32m"
#define LOG_COLOR_YELLOW        "\033[0;33m"
#define LOG_COLOR_BOLD_YELLOW   "\033[01;33m"
#define LOG_COLOR_BLUE          "\033[0;34m"
#define LOG_COLOR_BOLD_BLUE     "\033[1;34m"
#define LOG_COLOR_MAGENTA       "\033[0;35m"
#define LOG_COLOR_BOLD_MAGENTA  "\033[1;35m"
#define LOG_COLOR_CYAN          "\033[0;36m"
#define LOG_COLOR_BOLD_CYAN     "\033[1;36m"

#define NTS_ERR_OK				(0)
#define NTS_ERR_FAILED 			(-1)

void log_init(const char *logfilename);
void log_redirect_stderr(const char *stderrfilename);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvariadic-macros"
#define log_add_verbose(verbose_level, format, args...)  log__message(__FILE__, (uint32_t)__LINE__, verbose_level, format, ## args);
#define log_add(verbose_level, format, args...)  log__message(__FILE__, (uint32_t)__LINE__, -verbose_level, format, ## args);
#define log_error(format, args...)  log__message(__FILE__, (uint32_t)__LINE__, 0, format, ## args);
#pragma GCC diagnostic pop
void log_close(void);

//masked functions (use macros defined above)
void log__message(char const * const fname, uint32_t location, int verbose_level, const char *format, ...);
