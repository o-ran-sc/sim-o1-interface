/*************************************************************************
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

#include <string>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <cstdio>
#include <assert.h>

#include "regxstring.h"

using namespace std;

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


static string trim(std::string str){
    size_t i = 0,e = str.length();
    for(;i < e && std::isspace(str[i]);++i);
    size_t j = e;
    for(;j > i && std::isspace(str[j - 1]);--j);
    return (i < j ? str.substr(i,j - i) : "");
}

static string pre_handle(const string & str)
{
    string ret = trim(str);
    if(!ret.empty()) {
        if(ret[0] != '^') {
            ret.insert(ret.begin(),'^');
        }

        if(ret[ret.size() - 1] != '$') {
            ret.push_back('$');
        }
    }
    return ret;
}

static void rand_init(void) {
    unsigned int seed;
    FILE* urandom = fopen("/dev/urandom", "r");
    size_t ret = fread(&seed, sizeof(int), 1, urandom);
    (void)ret;
    fclose(urandom);
    srand(seed);
    srandom(seed);
}

static uint8_t *b64_decode(const char *data, size_t input_length, size_t *output_length) {
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

int main(int argc, const char ** argv)
{
    CRegxString regxstr;
    string regx64 = "";

    switch(argc) {
        case 2:
            rand_init();
            regx64 = argv[1];
            break;

        case 3:
            int pseudo_seed = 0;
            int i = 0;
            while(argv[1][i]) {
                pseudo_seed *= 10;
                pseudo_seed += argv[1][i] - '0';
                i++;
            }
            srand(pseudo_seed);
            srandom(pseudo_seed);
            regx64 = argv[2];
            break;
    }

    size_t ol;
    char *x = (char *)b64_decode(regx64.c_str(), strlen(regx64.c_str()), &ol);
    x[ol] = 0;

    string regx = x;
    free(x);

    regxstr.ParseRegx(pre_handle(regx).c_str());
    cout << regxstr.RandString() << endl;
    
    return 0;
}
