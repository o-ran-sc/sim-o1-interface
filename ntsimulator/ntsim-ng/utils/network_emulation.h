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

#include <stdint.h>

typedef struct {
    uint16_t limit;

    struct {
        uint16_t time;
        uint16_t jitter;
        uint16_t correlation;
        char *distribution;
    } delay;

    uint16_t loss;

    struct {
        uint16_t percentage;
        uint16_t correlation;
    } corruption;

    struct {
        uint16_t percentage;
        uint16_t correlation;
    } duplication;

    struct {
        uint16_t percentage;
        uint16_t correlation;
    } reordering;

    uint16_t rate;
} network_emultation_settings_t;

#define NETWORK_EMULATION_DEFAULT_LIMIT         "1000"

int network_emulation_init(void);
int network_emulation_update(const network_emultation_settings_t *s);
