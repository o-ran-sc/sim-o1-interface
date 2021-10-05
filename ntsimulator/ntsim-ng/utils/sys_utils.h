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

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define STANDARD_NETCONF_PORT   830
#define STANDARD_FTP_PORT       21
#define STANDARD_SFTP_PORT      22

#define KS_KEY_NAME                                 "melacon_server_key"
#define KS_CERT_NAME                                "melacon_server_cert"
#define SERVER_PUBLIC_SSH_KEY_PATH                  "/home/netconf/.ssh/melacon.server.key.pub"
#define SERVER_CERT_PATH                            "/home/netconf/.ssh/melacon.server.crt"

//filesystem functions
bool dir_exists(const char *path);
bool file_exists(const char *fname);
void file_touch(const char *fname, const char *content);    //content can be null for just-touching
char *file_read_content(const char *fname);

int get_int_from_string_with_default(const char *string, int default_value);
char *get_current_date_and_time(void);
long int get_microseconds_since_epoch(void);

//networking functions
bool get_local_ips(const char *ifname, char **ipv4, char **ipv6);
bool check_port_open(const char *host, uint16_t port);

char *b64_encode(const uint8_t *data, size_t input_length);
uint8_t *b64_decode(const char *data, size_t input_length, size_t *output_length);
char *str_replace(const char *orig, const char *rep, const char *with);

char *read_key(const char *filename);

void vsftp_daemon_init(void);
void vsftp_daemon_deinit(void);
void sftp_daemon_init(void);
void sftp_daemon_deinit(void);
