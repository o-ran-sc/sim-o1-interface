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

#include "rand_utils.h"
#include "log_utils.h"
#include "sys_utils.h"  //for b64_encode
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <assert.h>
#include <math.h>

#include "core/context.h"       //for context_get_identity_leafs_of_type
#include "core/framework.h"     //to check for no_rand

//private definitions
typedef struct __rand_range {
    union {
        int64_t num;
        double dec;
    } value;

    union {
        int64_t num;
        double dec;
    } min;

    union {
        int64_t num;
        double dec;
    } max;
} rand_range_t;

//private functions
static char *rand_string(int min_length, int max_length);
static struct lys_ident *rand_identity(struct lys_ident *type);

//random based on ranges
static int64_t rand_range_type_int_min(LY_DATA_TYPE type);
static int64_t rand_range_type_int_max(LY_DATA_TYPE type);
static rand_range_t rand_range(const char *range, const LY_DATA_TYPE type);

//for the following functions, the result should be freed by the user
static char *rand_date_and_time(void);
static char *rand_ipv4_address(void);
static char *rand_ipv6_address(void);
static char *rand_uuid(void);


void rand_init(void) {
    unsigned int seed;

    FILE* urandom = fopen("/dev/urandom", "r");
    if(urandom == 0) {
        log_error("failed to open /dev/urandom\n");
    }
    else {
        fread(&seed, sizeof(int), 1, urandom);
        fclose(urandom);
    }

    srand(seed);
    srandom(seed);

    log_add_verbose(2, "rand_init() was called and seed was initialized to %u\n", seed);
    if(RAND_MAX < 65536) {
        log_error("RAND_MAX is too low: %d\n", RAND_MAX);
    }
}

void rand_init_fixed(unsigned int seed) {
    srand(seed);
    srandom(seed);

    log_add_verbose(2, "rand_init_fixed() was called and seed was initialized to %u\n", seed);

    if(RAND_MAX < 65536) {
        log_error("RAND_MAX is too low: %d\n", RAND_MAX);
    }
}

char *rand_get_populate_value(const struct lys_type *type) {
    assert(type);

    char *ret = 0;

    if(type->der->module) {
        char *full_type = 0;
        
        asprintf(&full_type, "%s:%s", type->der->module->name, type->der->name);
        if(full_type == 0) {
            log_error("bad malloc\n");
            return 0;
        }

        if(strstr(full_type, "ietf-yang-types:date-and-time") != 0) {
            ret = rand_date_and_time();
        }
        else if(strstr(full_type, "ietf-inet-types:ipv4-address") != 0) {
            ret = rand_ipv4_address();
        }
        else if(strstr(full_type, "ietf-inet-types:ipv6-address") != 0) {
            ret = rand_ipv6_address();
        }
        else if((strstr(full_type, "ietf-yang-types:mac-address") != 0) || (strstr(full_type, "ietf-yang-types:phys-address") != 0)) {
            ret = rand_mac_address();
        }
        else if(strstr(full_type, "universal-id") != 0) {
            ret = rand_uuid();
        }
        
        free(full_type);
        if(ret) {
            return ret;
        }
    }

    switch(type->base) {
        case LY_TYPE_EMPTY:
        case LY_TYPE_BOOL:
            if(rand_bool()) {
                asprintf(&ret, "true");
                return ret;
            }
            else {
                asprintf(&ret, "false");
                return ret;
            }
            break;

        case LY_TYPE_DER:
            return rand_get_populate_value(&type->der->type);
            break;

        case LY_TYPE_ENUM:
            if(type->info.enums.count) {
                int i = rand_uint16() % type->info.enums.count; 
                asprintf(&ret, "%s", type->info.enums.enm[i].name);
                return ret;
            }
            else {
                return rand_get_populate_value(&type->der->type);
            }
            break;

        case LY_TYPE_IDENT: {
            while(!type->info.ident.ref) {
                type = &type->der->type;
            }
            struct lys_ident *ident = rand_identity(type->info.ident.ref[0]);
            if(ident == 0) {
                log_error("rand_identity failed\n");
                return 0;
            }

            asprintf(&ret, "%s:%s", ident->module->name, ident->name);
            return ret;    
        } break;

        case LY_TYPE_STRING: {
            int min_length = 1;
            int max_length = 255;
            char *expression = 0;
            bool found_length = false;

            do {
                if(type->info.str.length && !found_length) {
                    rand_range_t vals = rand_range(type->info.str.length->expr, LY_TYPE_UINT8);
                    min_length = vals.min.num;
                    max_length = vals.max.num;
                    if(min_length == 0) {
                        min_length = 1;
                    }

                    found_length = true;
                }

                if(type->info.str.pat_count) {
                    //checkAL aici de fapt trebuie sa facem AND si NOT intre toate expresiile, in functie de modifier
                    // int modifier = type->info.str.patterns[i].expr[0];
                    if(expression) {
                        free(expression);
                        expression = 0;
                    }
                    expression = strdup((char*)(type->info.str.patterns[0].expr + 1));
                }

                if(type->der) {
                    type = &type->der->type;
                }
                else {
                    break;
                }
            } while(1);

            if(expression) {
                char *ret = rand_regex(expression);
                if(ret == 0) {
                    log_error("rand_regex failed\n");
                    free(expression);
                    return 0;
                }

                while(strlen(ret) < min_length) {
                    char *add = rand_regex(expression);
                    if(add == 0) {
                        log_error("rand_regex failed\n");
                        free(expression);
                        free(ret);
                        return 0;
                    }

                    char *newret = 0;
                    asprintf(&newret, "%s%s", ret, add);
                    free(add);
                    free(ret);
                    ret = newret;
                }
                free(expression);

                if(ret == 0) {
                    log_error("rand_regex failed\n");
                    return 0;
                }

                if(max_length && (strlen(ret) > max_length)) {
                    ret[max_length] = 0;
                }

                return ret;
            }
            else {
                return rand_string(min_length, max_length);
            }
        } break;

        case LY_TYPE_INT8:
        case LY_TYPE_UINT8:
        case LY_TYPE_INT16:
        case LY_TYPE_UINT16:
        case LY_TYPE_INT32:
        case LY_TYPE_UINT32:
        case LY_TYPE_INT64:
        case LY_TYPE_UINT64: {
            const char *expr = 0;
            
            do {
                if(type->info.num.range) {
                    expr = type->info.num.range->expr;
                }    

                if(type->der) {
                    type = &type->der->type;
                }
                else {
                    break;
                }
            } while(1);

            int64_t r = rand_range(expr, type->base).value.num;
            if(type->base == LY_TYPE_UINT8) {
                asprintf(&ret, "%"PRIu8, (uint8_t)r);
            }
            else if(type->base == LY_TYPE_UINT16) {
                asprintf(&ret, "%"PRIu16, (uint16_t)r);
            }
            else if(type->base == LY_TYPE_UINT32) {
                asprintf(&ret, "%"PRIu32, (uint32_t)r);
            }
            else if(type->base == LY_TYPE_UINT64) {
                asprintf(&ret, "%"PRIu64, (uint64_t)r);
            }
            else if(type->base == LY_TYPE_INT8) {
                asprintf(&ret, "%"PRId8, (int8_t)r);
            }
            else if(type->base == LY_TYPE_INT16) {
                asprintf(&ret, "%"PRId16, (int16_t)r);
            }
            else if(type->base == LY_TYPE_INT32) {
                asprintf(&ret, "%"PRId32, (int32_t)r);
            }
            else if(type->base == LY_TYPE_INT64) {
                asprintf(&ret, "%"PRId64, (int64_t)r);
            }

            return ret;
        } break;

        case LY_TYPE_DEC64: {
            const char *expr = 0;
            int digits = -1;
            char fmt[10];
            char *ret = 0;
            
            do {
                if(type->info.dec64.range) {
                    expr = type->info.dec64.range->expr;
                }

                if(digits == -1) {
                    digits = type->info.dec64.dig;
                }

                if(type->der) {
                    type = &type->der->type;
                }
                else {
                    break;
                }
            } while(1);

            rand_range_t dr = rand_range(expr, LY_TYPE_DEC64);
            sprintf(fmt, "%%.%df", digits);

            //19 digits total, including decimal part
            int intdig = 19 - digits;
            double max_val = 9.223372036854775807;

            while(fabs(dr.value.dec) > (pow(10, intdig - 1) * max_val)) {
                dr.value.dec /= 10;
            }

            asprintf(&ret, fmt, dr.value.dec);
            return ret;
        } break;

        case LY_TYPE_BITS:
            ret = (char*)malloc(1);
            if(ret == 0) {
                log_error("malloc failed\n");
                return 0;
            }
            ret[0] = 0;

            for(int i = 0; i < type->info.bits.count; i++) {
                if(rand_bool()) {
                    const char *val = type->info.bits.bit[i].name;
                    bool first = (ret == 0);
                    ret = (char*)realloc(ret, sizeof(char) * (strlen(ret) + 1 + strlen(val) + 1));
                    if(ret == 0) {
                        log_error("malloc failed\n");
                        return 0;
                    }

                    if(!first) {
                        strcat(ret, " ");
                    }
                    strcat(ret, val);
                }
            }
            return ret;
            break;

        case LY_TYPE_BINARY: {
            int length = 1;
            char *ret = 0;

            do {
                if(type->info.binary.length) {
                    rand_range_t vals = rand_range(type->info.binary.length->expr, LY_TYPE_UINT16);
                    length = vals.min.num;
                    if(length == 0) {
                        length = 1;
                    }
                }

                if(type->der) {
                    type = &type->der->type;
                }
                else {
                    break;
                }
            } while(1);

            uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t) * length);
            if(!data) {
                log_error("bad malloc\n");
                return 0;
            }

            for(int i = 0; i < length; i++) {
                data[i] = rand_uint8();
            }

            ret = b64_encode(data, length);
            free(data);
            return ret;
        } break;

        case LY_TYPE_LEAFREF:
        case LY_TYPE_UNION:
        case LY_TYPE_INST:
            asprintf(&ret, "{late_resolve_%s}", type->der->name);
            log_error("needed: %s\n", ret);
            assert(0);
            return ret;
            break;

        case LY_TYPE_UNKNOWN:
        default:
            asprintf(&ret, "{unimplemented_%s}", type->der->name);
            log_error("can't generate random for: %s\n", type->der->name);
            assert(0);
            return ret;
            break;
    }
}

uint8_t rand_uint8(void) {
    return rand() % 256;
}

int8_t rand_int8(void) {
    return (int8_t)rand_uint8();
}

uint16_t rand_uint16(void) {
    return rand() % 65536;
}

int16_t rand_int16(void) {
    return (int16_t)rand_uint16();
}

uint32_t rand_uint32(void) {
    uint32_t x = rand_uint16();
    x <<= 16;
    x += rand_uint16();
    return x;
}

int32_t rand_int32(void) {
    return (int32_t)rand_uint32();
}

uint64_t rand_uint64(void) {
    uint64_t x = rand_uint32();
    x <<= 32;
    x += rand_uint32();
    return x;
}

int64_t rand_int64(void) {
    return (int64_t)rand_uint64();
}

bool rand_bool(void) {
    return ((rand() & 0x01) == 1);
}

char *rand_regex(const char *regexp) {
    assert(regexp);

    char buffer[8192];
    char *cmd = 0;
    static int run_time = 0;

    char *regexp64 = b64_encode((const unsigned char*)regexp, strlen(regexp));
    if(regexp64 == 0) {
        log_error("b64_encode failed\n");
        return 0;
    }

    if(framework_arguments.no_rand) {
        run_time++;
        asprintf(&cmd, "regxstring %d '%s'", run_time, regexp64);
    }
    else {
        asprintf(&cmd, "regxstring '%s'", regexp64);
    }
    free(regexp64);

    if(cmd == 0) {
        log_error("asprintf failed\n");
        return 0;
    }

    char last_char = ' ';
    while(last_char == ' ') {
        FILE* pipe = popen(cmd, "r");
        if (!pipe) {
            log_error("popen() failed\n");
            free(cmd);
            return 0;
        }

        fgets(buffer, sizeof(buffer), pipe);
        pclose(pipe);

        buffer[strlen(buffer) - 1] = 0;   //remove trailing \n
        last_char = buffer[strlen(buffer) - 1];
    }
        
    char *ret = strdup(buffer);
    free(cmd);

    return ret;
}

char *rand_mac_address(void) {
    char *ret = 0;

    asprintf(&ret, "%02x:%02x:%02x:%02x:%02x:%02x", rand_uint8(), rand_uint8(), rand_uint8(), rand_uint8(), rand_uint8(), rand_uint8());
    return ret;
}

static char *rand_string(int min_length, int max_length) {
    assert(min_length >= 0);
    assert(min_length <= max_length);

    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    int length = 1;
    if(min_length == max_length) {
        length = min_length;
    }
    else {
        if((framework_config.datastore_generate.debug_max_string_size) && (framework_config.datastore_generate.debug_max_string_size < max_length)) {
            max_length = framework_config.datastore_generate.debug_max_string_size;
        }

        length = min_length + rand_uint16() % (max_length - min_length);
    }

    char *ret = (char *)malloc(length + 1);
    if(!ret) {
        log_error("bad malloc\n");
        return 0;
    }

    for(int i = 0; i < length; i++) {
        ret[i] = charset[(rand_uint8() % (sizeof(charset) - 1))];
    }
    ret[length] = 0;
    return ret;
}

static struct lys_ident *rand_identity(struct lys_ident *type) {
    assert(type);

    struct lys_ident **found_identities;
    int total = context_get_identity_leafs_of_type(type, &found_identities);
    if(total == 0) {
        return 0;
    }

    int chosen = rand_uint16() % total;
    struct lys_ident *ret = found_identities[chosen];
    free(found_identities);

    return ret;
}


static int64_t rand_range_type_int_min(LY_DATA_TYPE type) {
    switch (type) {
        case LY_TYPE_UINT8:
            return 0;
            break;

        case LY_TYPE_INT8:
            return INT8_MIN;
            break;

        case LY_TYPE_UINT16:
            return 0;
            break;

        case LY_TYPE_INT16:
            return INT16_MIN;
            break;

        case LY_TYPE_UINT32:
            return 0;
            break;

        case LY_TYPE_INT32:
            return INT32_MIN;
            break;

        case LY_TYPE_UINT64:
            return 0;
            break;

        case LY_TYPE_INT64:
            return INT64_MIN;
            break;

        default:
            return 0;
            assert(0);
            break;
    }
}

static int64_t rand_range_type_int_max(LY_DATA_TYPE type) {
    switch (type) {
        case LY_TYPE_UINT8:
            return UINT8_MAX;
            break;

        case LY_TYPE_INT8:
            return INT8_MAX;
            break;

        case LY_TYPE_UINT16:
            return UINT16_MAX;
            break;

        case LY_TYPE_INT16:
            return INT16_MAX;
            break;

        case LY_TYPE_UINT32:
            return UINT32_MAX;
            break;

        case LY_TYPE_INT32:
            return INT32_MAX;
            break;

        case LY_TYPE_UINT64:
            return INT64_MAX;   //yes, intended
            break;

        case LY_TYPE_INT64:
            return INT64_MAX;
            break;

        default:
            return 0;
            assert(0);
            break;
    }
}

static rand_range_t rand_range(const char *range, const LY_DATA_TYPE type) {
    char *working_range = 0;
    rand_range_t ret;
    ret.value.num = 0;
    ret.min.num = 0;
    ret.max.num = 0;

    if (range) {
        //remove spaces
        char *rrange = (char*)malloc(sizeof(char) * (strlen(range) + 1));
        if (!rrange) {
            log_error("bad malloc\n");
            return ret;
        }

        int i = 0;
        int j = 0;
        while (range[i]) {
            if ((range[i] != ' ') && (range[i] != '\r') && (range[i] != '\n')) {
                rrange[j] = range[i];
                j++;
            }
            i++;
        }
        rrange[j] = 0;
 
        //split the range into OR ranges
        //first count how many different ranges exist
        int chosen_range = 1;
        char *search = strchr(rrange, '|');
        while (search) {
            chosen_range++;
            search = strchr(search + 1, '|');
        }

        //choose a random one
        chosen_range = rand_uint16() % chosen_range;
        int current_range = 0;
        char *token;
        token = strtok(rrange, "|");
        while (token) {
            if (current_range == chosen_range) {
                working_range = strdup(token);
            }
            current_range++;
            token = strtok(0, "|");
        }
        free(rrange);
    }

    //now parse working_range according to type
    if (type == LY_TYPE_DEC64) {
        double min = -922337203685477580.8;
        double max = 922337203685477580.7;
        bool negative = false;

        if (working_range) {
            min = 0;
            max = 0;

            int i = 0;
            if ((working_range[i] == 'm') || (working_range[i] == 'M')) {
                min = -922337203685477580.8;
                while (working_range[i] != '.') {
                    i++;
                }
            }
            else {
                if (working_range[i] == '-') {
                    negative = true;
                    i++;
                }

                while ((working_range[i] >= '0') && (working_range[i] <= '9')) {
                    min *= 10;
                    min += working_range[i] - '0';
                    i++;
                }
            }

            //working_range[i...] is either '.', ".." or \0
            if (working_range[i] == '.') {
                if (working_range[i + 1] != '.') {
                    i++;
                    int power = 0;
                    while ((working_range[i] >= '0') && (working_range[i] <= '9')) {
                        power--;
                        min += (working_range[i] - '0') * pow(10, power);
                        i++;
                    }
                }
                else {
                    i += 2;    //skip ".."
                }
            }

            if (negative) {
                min *= -1;
                negative = false;
            }
            
            if (working_range[i] == 0) {
                //single value
                max = min;
            }
            else {
                //there's also an upper value
                if ((working_range[i] == 'm') || (working_range[i] == 'M')) {
                    max = 922337203685477580.7;
                }
                else {
                    if (working_range[i] == '-') {
                        negative = true;
                        i++;
                    }

                    while ((working_range[i] >= '0') && (working_range[i] <= '9')) {
                        max *= 10;
                        max += working_range[i] - '0';
                        i++;
                    }
                }

                //working_range[i...] is either '.', or \0
                if (working_range[i] == '.') {
                    i++;
                    int power = 0;
                    while ((working_range[i] >= '0') && (working_range[i] <= '9')) {
                        power--;
                        max += (working_range[i] - '0') * pow(10, power);
                        i++;
                    }
                }

                if (negative) {
                    max *= -1;
                    negative = false;
                }
            }
        }

        ret.value.dec = rand() / 1.0 / RAND_MAX;
        ret.value.dec = (max - min) * ret.value.dec + min;
        ret.min.dec = min;
        ret.max.dec = max;
    }
    else {
        int64_t min = rand_range_type_int_min(type);
        int64_t max = rand_range_type_int_max(type);
        bool negative = false;

        if (working_range) {
            min = 0;
            max = 0;

            int i = 0;
            if ((working_range[i] == 'm') || (working_range[i] == 'M')) {
                min = rand_range_type_int_min(type);
                while (working_range[i] != '.') {
                    i++;
                }
            }
            else {
                if (working_range[i] == '-') {
                    negative = true;
                    i++;
                }

                while ((working_range[i] >= '0') && (working_range[i] <= '9')) {
                    min *= 10;
                    min += working_range[i] - '0';
                    i++;
                }
            }

            //working_range[i...] is either ".." or \0
            if (working_range[i] == '.') {
                i += 2;    //skip ".."
            }

            if (negative) {
                min *= -1;
                negative = false;
            }

            if (working_range[i] == 0) {
                //single value
                max = min;
            }
            else {
                //there's also an upper value
                if ((working_range[i] == 'm') || (working_range[i] == 'M')) {
                    max = rand_range_type_int_max(type);
                }
                else {
                    if (working_range[i] == '-') {
                        negative = true;
                        i++;
                    }

                    while ((working_range[i] >= '0') && (working_range[i] <= '9')) {
                        max *= 10;
                        max += working_range[i] - '0';
                        i++;
                    }
                }

                if (negative) {
                    max *= -1;
                    negative = false;
                }

            }
        }

        double ch = rand() / 1.0 / RAND_MAX;
        ret.value.num = (max - min) * ch + min;
        ret.min.num = min;
        ret.max.num = max;
    }

    free(working_range);

    return ret;
}

static char *rand_date_and_time(void) {
    time_t now = time(0);
    time_t start_date = 1577836800; //2020-01-01T00:00:00Z
    
    time_t t = start_date + rand_uint32() % (now - start_date);
    struct tm lt;
    (void)localtime_r(&t, &lt);

    char *ret = (char *)malloc(21);
    if(!ret) {
        return 0;
    }
    strftime(ret, 21, "%Y-%m-%dT%H:%M:%SZ", &lt);
    return ret;
}

static char *rand_ipv4_address(void) {
    char *ret = 0;
    uint8_t ip1 = rand_uint8();
    uint8_t ip2 = rand_uint8();
    uint8_t ip3 = rand_uint8();
    uint8_t ip4 = rand_uint8();

    asprintf(&ret, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
    return ret;
}

static char *rand_ipv6_address(void) {
    char *ret = 0;

    uint16_t ip1 = rand_uint16();
    uint16_t ip2 = rand_uint16();
    uint16_t ip3 = rand_uint16();
    uint16_t ip4 = rand_uint16();
    uint16_t ip5 = rand_uint16();
    uint16_t ip6 = rand_uint16();
    uint16_t ip7 = rand_uint16();
    uint16_t ip8 = rand_uint16();

    asprintf(&ret, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", ip1, ip2, ip3, ip4, ip5, ip6, ip7, ip8);
    return ret;
}

static char *rand_uuid(void) {
    char *ret = 0;

    //8-4-4-4-12
    uint32_t v1 = rand_uint32();
    uint16_t v2 = rand_uint16();
    uint16_t v3 = rand_uint16();
    uint16_t v4 = rand_uint16();
    uint16_t v5 = rand_uint16();
    uint32_t v6 = rand_uint32();

    asprintf(&ret, "%08x-%04x-%04x-%04x-%04x%08x", v1, v2, v3, v4, v5, v6);

    return ret;
}
