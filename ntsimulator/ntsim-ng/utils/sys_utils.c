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

#include "sys_utils.h"
#include "log_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <math.h>
#include <unistd.h>
#include <time.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <assert.h>

static char b64_encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                    'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                    '4', '5', '6', '7', '8', '9', '+', '/'};

static char b64_decoding_table[256] = {0};

static int b64_mod_table[] = {0, 2, 1};

bool dir_exists(const char *path) {
    assert(path);

    struct stat st = {0};
    return (stat(path, &st) != -1);
}

bool file_exists(const char *fname) {
    assert(fname);

    return (access(fname, F_OK) != -1);
}

void file_touch(const char *fname, const char *content) {
    assert(fname);

    FILE *f = fopen(fname, "w");
    if(f == 0) {
        log_error("fopen failed\n");
        return;
    }

    if(content) {
        fprintf(f, "%s", content);
    }
    fclose(f);
}

char *file_read_content(const char *fname) {
    assert(fname);

    char *buffer = 0;
    long length;
    FILE *f = fopen(fname, "rb");
    if(f) {
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);
        buffer = (char*)malloc(sizeof(char) * (length + 1));
        if(buffer) {
            fread(buffer, 1, length, f);
        }
        fclose(f);
    }
    buffer[length] = 0;

    return buffer;
}

int get_int_from_string_with_default(const char *string, int default_value) {
    int rc;
    int value = default_value;

    if(string != 0) {
        rc = sscanf(string, "%d", &value);
        if (rc != 1) {
            value = default_value;
        }
    }
    return value;
}

char *get_current_date_and_time(void) {
    char *date_and_time = 0;

	time_t t = time(0);
	struct tm tm = *localtime(&t);
	struct timeval tv;
	int millisec;

	gettimeofday(&tv, 0);
	millisec = lrint(tv.tv_usec/1000.0); // Round to nearest millisec
	if(millisec>=1000)	{ // Allow for rounding up to nearest second
		millisec -=1000;
		tv.tv_sec++;
		millisec /= 100;
	}

	asprintf(&date_and_time, "%04d-%02d-%02dT%02d:%02d:%02d.%01dZ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, millisec/100);

    return date_and_time;
}

long int get_microseconds_since_epoch(void) {
    time_t t = time(0);
    struct timeval tv;
    long int useconds;

    gettimeofday(&tv, 0);
    useconds = t*1000000 + tv.tv_usec; //add the microseconds to the seconds

    return useconds;
}


bool get_local_ips(const char *ifname, char **ipv4, char **ipv6) {
    assert(ifname);
    assert(ipv4);
    assert(ipv6);

    int s;
    struct ifaddrs *ifaddr;
    struct ifaddrs *ifa;
    char host[NI_MAXHOST];
    bool ret = true;

    *ipv4 = 0;
    *ipv6 = 0;

    if (getifaddrs(&ifaddr) == -1)  {
        ret = false;
        goto get_local_ips_free;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)  {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        s = getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if((strcmp(ifa->ifa_name, ifname) == 0) && (ifa->ifa_addr->sa_family == AF_INET)) {
            if (s != 0) {
                ret = false;
                goto get_local_ips_free;
            }
            
            *ipv4 = strdup(host);
            break;
        }
    }


    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)  {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        s = getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in6),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if((strcmp(ifa->ifa_name, ifname) == 0) && (ifa->ifa_addr->sa_family == AF_INET6)) {
            if (s != 0) {
                ret = false;
                goto get_local_ips_free;
            }
            
            *ipv6 = strdup(host);
            break;
        }
    }

    get_local_ips_free:
    if(ret == false) {
        free(*ipv4);
        free(*ipv6);
        *ipv4 = 0;
        *ipv6 = 0;
    }

    freeifaddrs(ifaddr);
    return ret;
}

bool check_port_open(const char *host, uint16_t port) {
    assert(host);

    int simpleSocket = 0;
    int returnStatus = 0; 
    struct addrinfo simpleServer;
    struct addrinfo *res;

    memset(&simpleServer, 0, sizeof simpleServer);
    simpleServer.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
    simpleServer.ai_socktype = SOCK_STREAM;
    simpleServer.ai_flags = AI_ADDRCONFIG;

    char sport[10];
    sprintf(sport, "%d", port);

    returnStatus = getaddrinfo(host, sport, &simpleServer, &res);
    if(returnStatus != 0) {
        return false;
    }

    simpleSocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(simpleSocket < 0) {
        freeaddrinfo(res);
        return false;
    }

    char s[INET6_ADDRSTRLEN];
    switch(res->ai_addr->sa_family) {
        case AF_INET: {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)res->ai_addr; 
            inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);
            returnStatus = connect(simpleSocket, res->ai_addr, res->ai_addrlen);
            break;
        }

        case AF_INET6: {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)res->ai_addr;
            inet_ntop(AF_INET6, &(addr_in6->sin6_addr), s, INET6_ADDRSTRLEN);
            returnStatus = connect(simpleSocket, res->ai_addr, res->ai_addrlen);
            break;
        }

        default:
            break;
    }

    freeaddrinfo(res);
    close(simpleSocket);
    if(returnStatus == 0) {    
        return true;
    }
    
    return false;
}

char *b64_encode(const uint8_t *data, size_t input_length) {
    assert(data);
    assert(input_length);

    int output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = (char *)malloc(sizeof(char) * (output_length + 1));
    if (encoded_data == 0) {
        return 0;
    }

    for (int i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = b64_encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = b64_encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = b64_encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = b64_encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < b64_mod_table[input_length % 3]; i++) {
        encoded_data[output_length - 1 - i] = '=';
    }

    encoded_data[output_length] = 0;

    return encoded_data;
}

uint8_t *b64_decode(const char *data, size_t input_length, size_t *output_length) {
    assert(data);
    assert(input_length);
    assert(output_length);

    int i, j;

    //one time compute decoding table
    if(b64_decoding_table['A'] == 0) {
        for(i = 0; i < 64; i++) {
            b64_decoding_table[(unsigned char)b64_encoding_table[i]] = i;
        }
    }

    if(input_length % 4 != 0) {
        return 0;
    }

    *output_length = input_length / 4 * 3;
    if(data[input_length - 1] == '=') {
        (*output_length )--;
    }
    if(data[input_length - 2] == '=') {
        (*output_length )--;
    }

    uint8_t *decoded_data = (uint8_t*)malloc(*output_length + 1);
    if(decoded_data == 0) {
        return 0;
    }

    for(i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : b64_decoding_table[(int)data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : b64_decoding_table[(int)data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : b64_decoding_table[(int)data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : b64_decoding_table[(int)data[i++]];
        uint32_t triple = ( sextet_a << 3 * 6 ) + ( sextet_b << 2 * 6 ) + ( sextet_c << 1 * 6 ) + ( sextet_d << 0 * 6 );

        if(j < *output_length) {
            decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        }

        if(j < *output_length) {
            decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        }

        if(j < *output_length) {
            decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
        }
    }

    return decoded_data;
}

char *str_replace(const char *orig, const char *rep, const char *with) {
    assert(orig);
    assert(rep);
    assert(with);

    char *result; // the return string
    const char *ins;    // the next insert point
    char *tmp;    // varies
    int len_rep;  // length of rep (the string to remove)
    int len_with; // length of with (the string to replace rep with)
    int len_front; // distance between rep and end of last rep
    int count;    // number of replacements

    // sanity checks and initialization
    if(!orig || !rep) {
        return 0;
    }

    len_rep = strlen(rep);
    if(len_rep == 0) {
        return 0; // empty rep causes infinite loop during count
    }

    if (!with) {
        with = "";
    }
    len_with = strlen(with);

    // count the number of replacements needed
    ins = orig;
    for(count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if(!result) {
        return 0;
    }

    // first time through the loop, all the variable are set correctly
    // from here on,
    //    tmp points to the end of the result string
    //    ins points to the next occurrence of rep in orig
    //    orig points to the remainder of orig after "end of rep"
    while(count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep; // move to next "end of rep"
    }

    strcpy(tmp, orig);
    return result;
}

char *read_key(const char *filename) {
    assert(filename);

    FILE * fp = 0;
    char * line = 0;
    size_t len = 0;
    ssize_t read;
    char *key_string = 0;

    fp = fopen(filename, "r");
    if(fp == 0) {
        log_error("could not open file %s\n", filename);
        return 0;
    }

    while((read = getline(&line, &len, fp)) != -1) {
        // we ignore the first and last lines forPrivate keys, Public keys and Certificates
        if(strstr(line, "PRIVATE KEY-----") || strstr(line, "PUBLIC KEY-----") || strstr(line, "CERTIFICATE-----")) {
            free(line);
            line = 0;
            len = 0;
            continue;
        }
        else {
            if(key_string) {
                key_string = (char *)realloc(key_string, strlen(key_string) + read + 1);
                if(key_string == 0) {
                    log_error("bad allocation\n");
                    free(line);
                    return 0;
                }

                strcat(key_string, line);
            }
            else {
                key_string = strdup(line);
                if(key_string == 0) {
                    log_error("bad allocation\n");
                    free(line);
                    return 0;
                }
            }
            
            free(line);
            line = 0;
            len = 0;
        }
    }

    fclose(fp);
    if(line) {
        free(line);
    }

    return key_string;
}

void vsftp_daemon_init(void) {
    system("/usr/sbin/vsftpd &");
}

void vsftp_daemon_deinit(void) {
    system("killall -9 vsftpd");
}

void sftp_daemon_init(void) {
    system("/usr/sbin/sshd -D &");
}

void sftp_daemon_deinit(void) {
    system("killall -9 sshd");
}
